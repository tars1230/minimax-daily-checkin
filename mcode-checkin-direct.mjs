#!/usr/bin/env node
/**
 * MiniMax 每日签到 —— 纯 HTTP 直连，不启动 MCode / 不拉起 TUI。
 *
 * 复刻 @minimax-ai/code 的 runtime 签到链路（chunk-F33I4QSG.js 的 cB/mB 类 + tS 签名器）：
 *   1) GET  {agentOrigin}/minimax-cloud/api/v1/signin/status   → 7 天签到面板
 *   2) 若今天处于 Claimable → POST {agentOrigin}/minimax-cloud/api/v1/signin/claim
 *
 * 鉴权：复用本机 MCode 已登录的 OAuth 凭据（~/.minimax/auth/<env>/<region>/mcode-public/）。
 *
 * ⚠️ 安全铁律（踩过 5 次坑换来的，务必保留）：
 *   1) OAuth 服务端对同一 (client_id, 用户) 只允许一个活跃授权，签发新的会顶掉旧的。
 *   2) refresh_token 是严格单次轮换 —— 用一次即作废。
 *   3) 因此：往共享凭据库写「已作废」的 refresh_token，会让桌面端下次续期拿到死 token
 *      → 401 → 弹登录窗把用户踢下线。
 *   4) 本脚本默认对凭据库「只读」。写回必须同时满足：
 *      - 显式 MCODE_CHECKIN_PERSIST_REFRESH=1
 *      - 持**上游同一把锁** <authDir>/auth.lock.lock（目录，mkdir 独占）并在锁内重读
 *      - 轮换前校验 state.status ∈ {authenticated, expired, refreshing} 且 generation 一致
 *      - 先写 auth.json（保住新 token），再写 auth-state.json（generation 同步）
 *      - 响应里没有新的 refresh_token → 绝不沿用旧值，直接判致命
 *      - 任一步失败 → 致命退出，绝不吞错；失败时 state 保持 expired，不回滚成 authenticated
 *   5) 进程探测 `isMCodeRunning()`：同时匹配正斜杠与反斜杠路径，排除自身 PID，
 *      探测失败一律当作「在运行」（宁可不签也不轮换）。
 *
 * 用法：
 *   node mcode-checkin-direct.mjs                    # 签到并打印结果
 *   node mcode-checkin-direct.mjs --json <path>      # 同时写 JSON 结果文件
 *   node mcode-checkin-direct.mjs --dry-run          # 只查状态，不领
 *
 * 退出码：0=claimed/already/unavailable(今天没得领也算正常)
 *         1=致命错误（需要人工介入，如执行 mcode login）
 *         2=claimable（仅 --dry-run：今天可领但本次没领）
 *         3=可重试（网络抖动 / 桌面端在跑 / 令牌过期，稍后重试即可）
 */
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import crypto from "node:crypto";
import http from "node:http";
import https from "node:https";
import { execFileSync } from "node:child_process";

const HOME =
  process.env.MINIMAX_DATA_DIR ||
  process.env.MAVIS_DATA_DIR ||
  process.env.MCODE_HOME ||
  path.join(os.homedir(), ".minimax");
const LOG_PATH = process.env.MCODE_CHECKIN_LOG || path.join(HOME, "logs", "mcode-checkin.log");
const LOG_MAX_BYTES = 2 * 1024 * 1024;

// ---- 来自 @minimax-ai/code 的常量 ----
const CLIENT_ID = "mcode-public";
const SCOPES = ["agent.default"];
const AUDIENCE = "agent-backend";
const AGENT_ORIGIN = {
  cn: process.env.MCODE_AGENT_ORIGIN || "https://agent.minimaxi.com",
  en: process.env.MCODE_AGENT_ORIGIN || "https://agent.minimax.io",
};
const ACCOUNT_ORIGIN = { cn: "https://account.minimaxi.com", en: "https://account.minimax.io" };

/**
 * OAuth token 端点：必须按**解析出来的** region 取（与签到端点同源）。
 * 之前只看 MAVIS_REGION 且默认 cn → 用户在 en 域登录时，签到打 agent.minimax.io（对），
 * 续期却打 account.minimaxi.com（错域）→ RT 不属于该域 → invalid_grant，
 * 还会把一个本来正常的 state 写成 expired。
 * MCODE_OAUTH_TOKEN_ENDPOINT 只是显式覆盖（沙箱测试用）。
 */
function oauthTokenEndpoint(region, buildEnv) {
  if (process.env.MCODE_OAUTH_TOKEN_ENDPOINT) return process.env.MCODE_OAUTH_TOKEN_ENDPOINT;
  const origin = ACCOUNT_ORIGIN[region] ?? ACCOUNT_ORIGIN.cn;
  return `${origin}/oauth2/token`;
}

// 面板天状态枚举（上游 lh）
const DAY_UPCOMING = 1;
const DAY_CLAIMABLE = 2;
const DAY_CLAIMED = 3;
const DAY_DISABLED = 4;
const VALID_DAY_STATUS = new Set([DAY_UPCOMING, DAY_CLAIMABLE, DAY_CLAIMED, DAY_DISABLED]);
// claim_result 枚举（上游 zY）
const RESULT_CLAIMED = 1;
const RESULT_ALREADY = 2;
const VALID_CLAIM_RESULT = new Set([RESULT_CLAIMED, RESULT_ALREADY]);
// scene 枚举（上游 Ix）
const VALID_SCENE = new Set([0, 1, 2, 3, 4]);
// auth-state 合法状态（上游 ct）
const VALID_AUTH_STATE = new Set([
  "authorizing", "authenticated", "refreshing", "scope_upgrade_required", "expired",
]);
// 允许轮换凭据的状态（上游 readUsableCredential 的同款规则）：
// 不在这个集合里 → 上游会抛 A（= 需要重新登录），脚本也不该去轮换。
// 典型反例：logging_out / logout_pending（用户刚注销）—— 轮换会把会话复活。
const ROTATABLE_STATUS = new Set(["authenticated", "expired", "refreshing"]);

const md5 = (s) => crypto.createHash("md5").update(s).digest("hex");
// token 过期后的宽限期：服务端通常还认一会儿，先试再说
const GRACE_MS = Number(process.env.MCODE_CHECKIN_GRACE_MS ?? 180000);

const args = process.argv.slice(2);
let jsonPath = null;
let dryRun = false;
for (let i = 0; i < args.length; i++) {
  if (args[i] === "--json") jsonPath = args[i + 1];
  if (args[i] === "--dry-run") dryRun = true;
}

// ================= 日志 =================

/** 只记 token 的 md5 指纹，不记明文片段（上游有脱敏正则） */
const fingerprint = (tok) => (tok ? md5(String(tok)).slice(0, 8) : "none");

const log = (m) => {
  const line = `[${new Date().toISOString()}] ${m}\n`;
  try {
    fs.mkdirSync(path.dirname(LOG_PATH), { recursive: true });
    // 轮转：超过上限就把旧文件挪成 .1，避免无限增长
    try {
      const st = fs.statSync(LOG_PATH);
      if (st.size > LOG_MAX_BYTES) {
        fs.renameSync(LOG_PATH, `${LOG_PATH}.1`);
      }
    } catch {}
    fs.appendFileSync(LOG_PATH, line);
  } catch {}
};

// ================= 极简 HTTPS 客户端 =================

/**
 * 刻意不用全局 fetch（undici）：它的连接池会在 Windows 退出阶段触发
 * libuv 断言 "UV_HANDLE_CLOSING"（src/win/async.c），导致退出码变 0xC0000409。
 */
function httpsRequest(url, { method = "GET", headers = {}, body = null, timeoutMs = 30000 } = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    // 本地沙箱测试用 http，其余一律 https
    const mod = u.protocol === "http:" ? http : https;
    const req = mod.request(
      {
        hostname: u.hostname,
        port: u.port || (u.protocol === "http:" ? 80 : 443),
        path: `${u.pathname}${u.search}`,
        method,
        headers,
        agent: false, // 不复用连接，避免残留 socket
      },
      (res) => {
        const chunks = [];
        res.on("data", (d) => chunks.push(d));
        res.on("end", () =>
          resolve({ status: res.statusCode, text: Buffer.concat(chunks).toString("utf8") })
        );
      }
    );
    const timer = setTimeout(() => {
      req.destroy(new Error(`request timed out after ${timeoutMs}ms`));
    }, timeoutMs);
    req.on("error", (e) => {
      clearTimeout(timer);
      // 网络层故障一律视为可重试（M4）：定时任务应该「稍后重试」而不是报硬故障
      e.retryable = true;
      e.stage = e.stage ?? "network";
      reject(e);
    });
    req.on("close", () => clearTimeout(timer));
    if (body != null) req.write(body);
    req.end();
  });
}

// ================= 凭据读取（全部只读） =================

function readJsonSafe(p) {
  try { return JSON.parse(fs.readFileSync(p, "utf8")); } catch { return null; }
}

/**
 * 定位凭据目录。用 auth-state.json 的 status 过滤，优先当前 region，
 * 避免挑到一个陈旧 / 属于另一个域的目录（上游 at() 的做法）。
 */
function resolveAuthDir() {
  const base = path.join(HOME, "auth");
  const regions = [process.env.MAVIS_REGION, "cn", "en"].filter(Boolean);
  const envs = ["prod", "staging", "test", "dev"];
  const candidates = [];
  for (const env of envs) {
    for (const region of regions) candidates.push(path.join(base, env, region, CLIENT_ID));
  }
  // 首选：状态文件合法的目录
  for (const dir of candidates) {
    if (!fs.existsSync(path.join(dir, "auth.json"))) continue;
    const st = readJsonSafe(path.join(dir, "auth-state.json"));
    if (!st || VALID_AUTH_STATE.has(st.status)) return dir;
  }
  // 退化：只要有 auth.json
  for (const dir of candidates) {
    if (fs.existsSync(path.join(dir, "auth.json"))) return dir;
  }
  // D3：auth.json 整个没了，但还留着 pending（那里面可能是唯一还活着的 RT）→ 仍然认这个目录
  for (const dir of candidates) {
    if (fs.existsSync(path.join(dir, "auth.json.pending"))) return dir;
  }
  return null;
}

/**
 * pending 里有没有可用的凭据（第六轮 D3）：
 * auth.json 损坏 / 凭据丢失时，pending 可能是**唯一**还活着的 refresh_token ——
 * 必须给恢复流程留个机会，不能一看到「没有 access token」就要求用户重新登录。
 */
function pendingCredential(authDir, recordKey) {
  if (!authDir || !recordKey) return null;
  try {
    const pendingStore = readJsonSafe(path.join(authDir, "auth.json.pending"));
    const pRec = pendingStore?.records?.[recordKey];
    if (!pRec) return null;
    if (!pRec.refreshToken && !pRec.accessToken) return null;
    return pRec;
  } catch {
    return null;
  }
}

/**
 * realUserID：多来源兜底。
 * 注意：ID 可能超过 2^53，JSON.parse 会丢精度，所以一律按字符串处理并校验。
 */
function resolveRealUserID(authDir, region, buildEnv) {
  const tries = [];
  // 1) cli-auth 身份文件（优先用正则取原始数字串，避免 JSON.parse 丢精度）
  if (authDir) {
    const idFile = path.join(HOME, "cli-auth", buildEnv, region, "account-identity.json");
    try {
      const raw = fs.readFileSync(idFile, "utf8");
      const m = raw.match(/"realUserID"\s*:\s*"?(\d+)"?/);
      if (m && /"status"\s*:\s*"verified"/.test(raw)) tries.push(m[1]);
    } catch {}
  }
  // 2) mcode-tools 凭据的 subject（L11：同样用正则取原始数字串，
  //    避免 JSON.parse 把 >2^53 的 realUserID 舍入）
  try {
    const raw = fs.readFileSync(path.join(HOME, "integrations", "mcode-tools", "credentials.json"), "utf8");
    const m = raw.match(/"subject"\s*:\s*"?(\d+)"?/);
    if (m) tries.push(m[1]);
  } catch {}
  // 3) local-runtime 身份
  try {
    const raw = fs.readFileSync(path.join(HOME, "local-runtime.auth.json"), "utf8");
    const m = raw.match(/"realUserID"\s*:\s*"?(\d+)"?/);
    if (m) tries.push(m[1]);
  } catch {}

  for (const t of tries) {
    const s = String(t).trim();
    if (/^\d{10,24}$/.test(s)) return s;
  }
  return null;
}

/**
 * 上游的凭据记录键（chunk-77VGHMFO.js 的 H()），已对本机真实 store 验证一致：
 *   service = `com.minimax.mcode.oauth.<buildEnv>.<region>`
 *   account = base64url(sha256(`${authHome}\0${clientId}`))    // authHome = resolve(dataDir, "auth")
 *   key     = service + "\0" + account
 */
function upstreamCredentialKey(authHome, buildEnv, region) {
  const service = `com.minimax.mcode.oauth.${buildEnv}.${region}`;
  const account = crypto.createHash("sha256").update(`${authHome}\0${CLIENT_ID}`).digest("base64url");
  return `${service}\0${account}`;
}

function loadStore(authDir) {
  const store = readJsonSafe(path.join(authDir, "auth.json"));
  const state = readJsonSafe(path.join(authDir, "auth-state.json"));
  const records = store?.records ?? {};
  // L5：state 缺失时不要默认成 cn/prod —— 目录路径本身就编码了 buildEnv/region
  const parts = path.resolve(authDir).split(path.sep);
  const dirRegion = parts.length >= 2 ? parts[parts.length - 2] : null;
  const dirBuildEnv = parts.length >= 3 ? parts[parts.length - 3] : null;
  const region = state?.region ?? dirRegion ?? "cn";
  const buildEnv = state?.buildEnv ?? dirBuildEnv ?? "prod";
  // L4 / C11：优先用上游公式算出的精确键。
  // 取不到说明命名空间/区域已经变了 —— 上游只用精确键。
  // 若 store 里只有一条记录，可以安全地用它（并告警）；有多条则不能猜（可能轮换到别的账号）。
  const exact = upstreamCredentialKey(path.resolve(HOME, "auth"), buildEnv, region);
  const allKeys = Object.keys(records);
  let key = null;
  let ambiguous = false;
  if (records[exact]) key = exact;
  else if (allKeys.length === 1) {
    key = allKeys[0];
    log(`warn: the upstream credential key was not found; using the only record in the store`);
  } else if (allKeys.length > 1) {
    ambiguous = true;
    key = allKeys[0];
  } else {
    // D3：store 损坏或为空 → 仍然用上游精确键，好让 pending 能被找到并救回会话
    key = exact;
  }
  const record = key ? records[key] ?? null : null;
  return { store, state, record, recordKey: key, region, buildEnv, ambiguous };
}

// ================= 原子写（对齐上游 I() 的语义） =================

/**
 * 强原子写：open(wx) 独占创建 → write → fsync → close → rename。
 * 失败时清理 tmp。上游用同样的顺序（chunk-77VGHMFO.js 的 I()）。
 */
function atomicWriteFile(target, content, mode = 0o600) {
  // tmp 名带随机串：同毫秒并发时 open(wx) 会撞名报 EEXIST
  const tmp = `${target}.${process.pid}.${Date.now()}.${crypto.randomBytes(4).toString("hex")}.tmp`;
  let fd;
  try {
    fd = fs.openSync(tmp, "wx", mode);
    fs.writeFileSync(fd, content, { encoding: "utf8" });
    try { fs.fsyncSync(fd); } catch {}
    fs.closeSync(fd);
    fd = undefined;
    fs.renameSync(tmp, target);
  } catch (e) {
    if (fd !== undefined) { try { fs.closeSync(fd); } catch {} }
    try { fs.unlinkSync(tmp); } catch {}
    throw e;
  }
}

/** Windows 上 rename 覆盖被占用/只读的目标会 EPERM/EBUSY/EACCES —— 属瞬时故障，可重试 */
const RETRYABLE_FS_CODES = new Set(["EPERM", "EBUSY", "EACCES", "EAGAIN", "ENOTEMPTY"]);

/**
 * 最后一档兜底：直接覆盖写目标文件（不走 rename）+ fsync，然后**回读校验**。
 * 只有「rename 长期被占用（杀软/索引器/桌面端持有句柄）但文件本身可写」时才会走到这里。
 *
 * ⚠️ D2：覆盖写会**先截断原文件**。一旦写到一半失败，auth.json 就成了半截 JSON ——
 *    上游读不出来 → getStatus() 判 "error" → **强制重登**；而且 store 不可解析时
 *    pending 也认不出来（records[key] 取不到）→ 连我们自己留的新 RT 都救不回来。
 *    所以必须：① 写前备份原字节；② 失败/校验不过时**尽力把原内容写回去**（保 parseability）；
 *    ③ 校验标准是「能 JSON.parse 且关键字段齐全」，而不是字节相等。
 */
function directOverwriteFile(target, content, mode = 0o600) {
  let original = null;
  try {
    original = fs.readFileSync(target);
  } catch {}
  const restoreOriginal = () => {
    if (original === null) return false;
    try {
      const fd = fs.openSync(target, "w", mode);
      try {
        fs.writeFileSync(fd, original);
        try { fs.fsyncSync(fd); } catch {}
      } finally {
        fs.closeSync(fd);
      }
      return true;
    } catch {
      return false;
    }
  };

  try {
    const fd = fs.openSync(target, "w", mode);
    try {
      fs.writeFileSync(fd, content, { encoding: "utf8" });
      try { fs.fsyncSync(fd); } catch {}
    } finally {
      fs.closeSync(fd);
    }
  } catch (e) {
    restoreOriginal();
    throw e;
  }

  const back = fs.readFileSync(target, "utf8");
  if (back === content) return;
  // 字节不等：只要还是**合法 JSON**且关键字段齐全，就接受（换行/编码差异不算失败）
  let ok = false;
  try {
    const parsed = JSON.parse(back);
    ok = !!parsed && typeof parsed === "object";
  } catch {
    ok = false;
  }
  if (ok) {
    log(`warn: the direct overwrite of ${path.basename(target)} differs byte-wise from the intended content but is valid JSON`);
    return;
  }
  // 不可解析 = store 坏了 = 上游会强制重登 → 尽力还原原内容
  const restored = restoreOriginal();
  throw new Error(
    `direct overwrite of ${path.basename(target)} did not verify` +
      (restored ? " (the original content was restored)" : " (the original content could NOT be restored)")
  );
}

/**
 * 带指数退避重试的原子写。
 *
 * 这是「唯一会真正丢掉新 refresh_token」的路径 —— 服务端轮换后旧 RT 立刻作废，
 * 而新 RT 只在内存里。Windows 的 rename EPERM（杀软/索引器/只读位）是高频瞬时故障，
 * 必须容忍重试，而不是一次失败就把会话送走。
 *
 * 第五轮 S3：写 auth.json 的预算是**会话存亡**级别的 —— 重试窗口太短 = 库里留下死 RT
 * → 桌面端下次启动 401 → 用户被踢回登录页。所以预算拉到 ~10s，并留一档「直接覆盖写」兜底。
 */
async function atomicWriteFileWithRetry(
  target,
  content,
  { attempts = 5, mode = 0o600, baseDelayMs = 50, maxDelayMs = 2000, fallbackDirect = false } = {}
) {
  let lastErr = null;
  // 测试钩子：强制走「直接覆盖写」这条兜底路径（平时用不到）
  if (process.env.MCODE_CHECKIN_FORCE_DIRECT_WRITE === "1") {
    directOverwriteFile(target, content, mode);
    return;
  }
  for (let i = 0; i < attempts; i++) {
    try {
      atomicWriteFile(target, content, mode);
      return;
    } catch (e) {
      lastErr = e;
      if (!RETRYABLE_FS_CODES.has(e?.code)) throw e;
      if (i < attempts - 1) {
        const d = Math.min(maxDelayMs, baseDelayMs * 2 ** i); // 默认 50/100/200/400ms…封顶 maxDelayMs
        await new Promise((r) => setTimeout(r, d));
        log(`warn: atomic write to ${path.basename(target)} failed with ${e?.code}, retrying (${i + 1}/${attempts - 1})`);
      }
    }
  }
  if (fallbackDirect) {
    // 最后一档：直接覆盖写 + 回读校验（rename 被长期占用时只有这条能救）
    try {
      directOverwriteFile(target, content, mode);
      log(
        `warn: atomic rename to ${path.basename(target)} kept failing; fell back to a direct overwrite (verified by read-back)`
      );
      return;
    } catch (e) {
      lastErr = e;
    }
  }
  throw lastErr;
}

// 写 auth.json 的重试预算（会话存亡级别，第五轮 S3）
const WRITE_RETRY_ATTEMPTS = Math.max(1, Number(process.env.MCODE_CHECKIN_WRITE_ATTEMPTS ?? 8));
const WRITE_RETRY_MAX_DELAY_MS = Math.max(0, Number(process.env.MCODE_CHECKIN_WRITE_MAX_DELAY_MS ?? 2000));

/**
 * 写 auth.json 的**统一入口**（第六轮 D4）：
 * 三处写 auth.json 的地方必须共用同一套预算与兜底。
 * 否则 pending 恢复路径 / C2 路径会沿用 0.75s 的默认预算 ——
 * 那两条路径写失败 = 新 RT 只在 pending 里、store 里是死 RT → 桌面端下次续期 401 → 用户被踢。
 */
async function writeAuthJson(authJsonPath, payload) {
  return atomicWriteFileWithRetry(authJsonPath, JSON.stringify(payload, null, 2), {
    attempts: WRITE_RETRY_ATTEMPTS,
    baseDelayMs: 250,
    maxDelayMs: WRITE_RETRY_MAX_DELAY_MS,
    fallbackDirect: true,
  });
}

// ================= 独占锁（对齐上游 proper-lockfile 语义） =================

/**
 * 一次加锁尝试。语义与上游 proper-lockfile 的 oi() 逐项对齐：
 *   - mkdir 独占创建；EEXIST = 已加锁
 *   - 陈旧判定看锁**目录**的 mtime
 *   - 回收陈旧锁后**只再试一次**（上游用 stale:0 收敛，绝不二次回收）
 *   - 锁目录刚消失（ENOENT）→ 立刻再试一次
 * 返回 true = 拿到锁；false = 锁被别人占着（未陈旧）
 */
function tryAcquireLock(lockDir, staleMs) {
  let stale = staleMs;
  for (;;) {
    try {
      fs.mkdirSync(lockDir);
      return true;
    } catch (e) {
      if (e?.code !== "EEXIST") throw e;
      if (stale <= 0) return false;
      let st = null;
      try {
        st = fs.statSync(lockDir);
      } catch (err) {
        if (err?.code === "ENOENT") { stale = 0; continue; } // 刚被别人释放 -> 立刻再试一次
        throw err;
      }
      if (st.mtimeMs >= Date.now() - stale) return false; // 锁是新的 -> 让给持有者
      // 陈旧 -> 回收。
      // ⚠️ 锁目录必须保持「空目录」（上游 proper-lockfile 的 rmdir 不是递归的，
      //    非空目录会让上游回收失败 → 桌面端永久拿不到锁 → 刷不到 token → 被踢回登录页）。
      //    这里额外清理掉早期版本可能残留的 owner-* 文件，避免留下永久死锁。
      try {
        fs.rmdirSync(lockDir);
      } catch (rmErr) {
        if (rmErr?.code === "ENOTEMPTY" || rmErr?.code === "EEXIST") {
          try {
            for (const f of fs.readdirSync(lockDir)) {
              if (f.startsWith("owner-")) fs.unlinkSync(path.join(lockDir, f));
            }
            fs.rmdirSync(lockDir);
          } catch {}
        } else {
          throw rmErr;
        }
      }
      stale = 0; // 回收后只再试一次，绝不二次回收（上游同款）
    }
  }
}

/**
 * 与上游逐项对齐（chunk-77VGHMFO.js 的 g.withLock + 内嵌 proper-lockfile）：
 *
 *   - 上游 touch 的是 <authDir>/auth.lock 这个**文件**（只是让路径稳定存在，
 *     内容不动、也不删）；真正的互斥体是 <authDir>/auth.lock.lock 这个**目录**
 *     —— proper-lockfile 用 mkdir 独占创建，EEXIST 即「已加锁」。
 *   - 早期版本误把 auth.lock 文件本身当锁：既不与上游互斥，又会删掉桌面端的占位文件。
 *   - 早期版本把 owner 标记写在锁目录**里面** → 目录非空 → 上游的 rmdir 回收不了
 *     → 桌面端永久 ELOCKED → 刷不到 token → 被踢回登录页。**已修正：锁目录保持空目录**，
 *     失锁检测改用上游同款的「锁目录 mtime 比对法」。
 *   - 陈旧判定看锁**目录**的 mtime；staleMs=30000（与上游 `n.staleMs ?? 3e4` 一致）。
 *   - 重试退避与上游一致：factor=1.15、minTimeout=5ms、maxTimeout=250ms、retries=120。
 *
 * 关键意义：上游 getAccessToken()/handleUnauthorized() 刷新凭据时**全程持同一把锁**，
 * 并且**在锁内重读**凭据（上游绝不会拿着锁外读到的旧 refresh_token 去轮换）。
 * 所以两边天然互斥 —— 不会出现「桌面端已读走旧 refresh_token，我再轮换一次」，
 * 也就不会触发 invalid_grant 把桌面端逼回登录页。
 *
 * @param fn 接收一个 guard：{ assertHeld() }，在每次写凭据之前调用，
 *           以便「失锁」能被及时发现，而不是写完才知道。
 */
async function withAuthLock(lockPath, fn, { staleMs = 30000, retries = 120 } = {}) {
  fs.mkdirSync(path.dirname(lockPath), { recursive: true });
  // 上游的 touch：确保 lockPath 存在，且绝不删除它
  try { fs.closeSync(fs.openSync(lockPath, "a", 0o600)); } catch {}
  const lockDir = `${lockPath}.lock`;

  // 退避：与上游 proper-lockfile 的 retries/factor/minTimeout/maxTimeout 一致
  let delay = 5;
  let acquired = false;
  for (let attempt = 0; attempt < retries && !acquired; attempt++) {
    acquired = tryAcquireLock(lockDir, staleMs);
    if (acquired) break;
    await new Promise((r) => setTimeout(r, delay));
    delay = Math.min(250, Math.ceil(delay * 1.15));
  }
  if (!acquired) throw new Error(`could not acquire auth lock: ${lockDir}`);

  // ---- 失锁检测：上游 proper-lockfile 的同款做法（比对锁目录 mtime）----
  // 上游每次 update 都会 stat 锁目录，发现 mtime 不是自己设的那个值就判 ECOMPROMISED。
  // 我们不做任何写入锁目录的动作，因此锁目录始终是空目录（与上游同构）。
  const lockMtime = () => {
    try { return fs.statSync(lockDir).mtimeMs; } catch { return null; }
  };
  let compromised = false;
  const setLockMtime = (initial = false) => {
    // 上游 getMtime()：**首次**探测用「下一整秒 +5ms」（用来探测 FS 的时间精度），
    // 之后的心跳用 Date.now()（上游 getMtime("ms")）。
    // ⚠️ 如果心跳也整秒量化，在 1 秒粒度的文件系统（FAT/exFAT/网络盘）上会被截断，
    //    然后「我设的值」与「stat 到的值」永远差 5ms → 每次续期都被自己判成失锁。
    const t = initial ? new Date(Math.ceil(Date.now() / 1000) * 1000 + 5) : new Date();
    fs.utimesSync(lockDir, t, t);
  };
  let myMtime = lockMtime();
  try {
    setLockMtime(true);
    // 写完之后**重新 stat 一次**，用观测到的值做基准（FS 可能截断精度）
    myMtime = lockMtime();
  } catch {}

  const assertHeld = () => {
    if (compromised) {
      throw new Error(
        "auth lock was lost (compromised) — another process took the lock. Aborting before writing."
      );
    }
    // 实时复核：心跳最多有 stale/6 的检测延迟，写凭据之前必须当场确认一次，
    // 否则「失锁后仍把凭据写进去」会覆盖对方刚写的新凭据。
    const now = lockMtime();
    if (now === null) {
      compromised = true;
      throw new Error("auth lock directory disappeared — the lock was taken by another process.");
    }
    if (myMtime !== null && Math.abs(now - myMtime) > 1) {
      compromised = true;
      throw new Error(
        "auth lock was taken by another process (lock mtime changed) — aborting before writing."
      );
    }
  };

  // 心跳：刷新锁目录 mtime，并校验「mtime 仍是我设的那个」→ 失锁即置 compromised。
  // 间隔取 stale/6（5s），比上游的 stale/2 更密，缩短失锁检测窗口。
  const heartbeat = setInterval(() => {
    try {
      const now = lockMtime();
      if (now === null) { compromised = true; return; }
      if (myMtime !== null && Math.abs(now - myMtime) > 1) { compromised = true; return; }
      setLockMtime();
      myMtime = lockMtime(); // 重新观测（FS 可能截断精度）
    } catch {
      // 刷 mtime 失败：锁目录可能已被对方删了/换了 → 判失锁
      compromised = true;
    }
  }, Math.max(1000, Math.floor(staleMs / 6)));
  heartbeat.unref?.();

  try {
    const out = await fn({ assertHeld });
    if (compromised) {
      throw new Error(
        "auth lock was lost (compromised) during the critical section — another process took the lock. " +
          "Aborting without trusting the result."
      );
    }
    return out;
  } finally {
    clearInterval(heartbeat);
    // 释放：只 rmdir（锁目录是空的）。若已经不是我们的锁，绝不能删别人的。
    // S11：原来「myMtime === null」（首次 stat 失败）就永远不 rmdir → 锁目录泄漏
    //      → 桌面端拿到 ELOCKED，最多卡 30s（stale 阈值）才能自愈。
    //      我们从不往锁目录里写任何东西，所以「目录还在且为空」就足以证明是我们的。
    try {
      const now = lockMtime();
      if (now === null) {
        // 目录已经不在了（被别人回收或删除）→ 没什么可释放的
      } else if (myMtime !== null && Math.abs(now - myMtime) > 1) {
        log("warn: auth lock mtime changed — not removing the lock directory (it may belong to another process)");
      } else {
        const entries = fs.readdirSync(lockDir);
        if (entries.length === 0) {
          fs.rmdirSync(lockDir);
        } else {
          log(`warn: the auth lock directory is not empty (${entries.join(", ")}) — leaving it in place`);
        }
      }
    } catch (e) {
      log(`warn: could not release the auth lock: ${e?.message ?? e}`);
    }
  }
}

/**
 * 写回顺序的硬约束（记在这里，免得以后有人「顺手优化」回去）：
 *
 * ⚠️ 绝不能为了「两个文件 generation 一致」而在写失败时回滚 auth.json。
 * 服务端一旦轮换 refresh_token，旧 token 立刻作废，而新 token 只存在于我们手里。
 * 回滚 auth.json = 把已作废的旧 token 写回去 → 桌面端必然 401 → 被踢回登录页。
 * 这比「短暂 generation 不一致」严重得多。
 *
 * 固定顺序：先写 auth.json（保住新 token），再写 auth-state.json（对齐 generation）。
 * 第二步失败时状态会停在 refreshing + generation 落后，
 * 上游的 recoverInterruptedCredentialCommit() 专门处理这个中间态、能自愈。
 */

// ================= OAuth 续期 =================

/**
 * 解 JWT payload（上游 Ve）。非 JWT / 解不开就返回 undefined。
 */
function decodeJwtPayload(token) {
  try {
    const parts = String(token).split(".");
    if (parts.length !== 3 || !parts[1]) return undefined;
    const obj = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
    return obj && typeof obj === "object" && !Array.isArray(obj) ? obj : undefined;
  } catch {
    return undefined;
  }
}

/**
 * 换 access_token。请求参数与上游 refreshToken() 逐项一致：
 *   grant_type=refresh_token, refresh_token, client_id, scope, audience
 *
 * ⚠️ 这里刻意比上游宽松：上游 se() 会因为 token_type / expires_in / scope 不合规
 * 直接抛 invalid_token_response。但**服务端一旦轮换 refresh_token，旧 token 立刻作废**，
 * 此时若我们抛错而不落盘，新 token 就丢了 → 桌面端必然被踢回登录页。
 * 所以这里只在「连 access_token 都没拿到」（= 无从落盘）时才失败，
 * 其余字段不合规一律降级为告警，仍然照常落盘。
 */
/**
 * 脱敏：错误信息/响应片段里可能带 token 明文。
 * 上游有同样的正则（chunk-77VGHMFO.js 的 Pe）。
 */
const SENSITIVE_KEY_RE = /(access[_-]?token|refresh[_-]?token|id[_-]?token|device[_-]?code|code[_-]?verifier)/iu;
function redactSensitive(text) {
  if (typeof text !== "string") return String(text ?? "");
  return text
    .replace(
      /("(?:access[_-]?token|refresh[_-]?token|id[_-]?token|device[_-]?code|code[_-]?verifier)"\s*:\s*")([^"]*)(")/gi,
      "$1***$3"
    )
    .replace(/\b(mm(?:oat|ort)_)[A-Za-z0-9_-]+/g, "$1***");
}

/**
 * 换 access_token。请求参数与上游 refreshToken() 逐项一致：
 *   grant_type=refresh_token, refresh_token, client_id, scope, audience
 *
 * ⚠️ 取舍说明（与上游刻意不同）：
 *   上游 se() 会因为 token_type / expires_in / scope 不合规直接抛 invalid_token_response。
 *   但**服务端一旦轮换 refresh_token，旧 token 立刻作废**，此刻抛错 = 新 token 丢失
 *   = 桌面端被踢下线。所以这里只在「连 access_token 都没拿到」（= 无从落盘）时失败，
 *   其余不合规一律降级为告警 + 保守兜底值，仍然照常落盘。
 *
 * ⚠️ 但有一条兜底是绝对禁止的（opencode S1）：**响应里没有 refresh_token 时，
 *   绝不能沿用旧值** —— 旧值此刻已经作废，写回 store 等于把死 token 交给桌面端。
 *   这种情况直接判定为致命，交由调用方处理。
 */
async function refreshAccessToken({ record, region, endpoint }) {
  if (!record?.refreshToken) throw new Error("no refresh_token available");
  const form = new URLSearchParams({
    grant_type: "refresh_token",
    refresh_token: record.refreshToken,
    client_id: CLIENT_ID,
    scope: SCOPES.join(" "),
    audience: AUDIENCE,
  });
  const res = await httpsRequest(endpoint, {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/x-www-form-urlencoded",
      "Content-Length": Buffer.byteLength(form.toString()),
    },
    body: form.toString(),
    // ≤5s：临界区必须显著短于上游的 stale 阈值（30s）与重试预算（≈24s），
    // 否则桌面端会把自己的锁判成陈旧并抢走（叠加 C3/C4 = 跨进程覆盖）。
    timeoutMs: Number(process.env.MCODE_CHECKIN_OAUTH_TIMEOUT_MS ?? 5000),
  });
  const text = res.text;
  if (res.status < 200 || res.status >= 300) {
    const e = new Error(`token refresh failed HTTP ${res.status}: ${redactSensitive(text.slice(0, 300))}`);
    e.status = res.status;
    e.stage = "oauth";
    // 4xx（除 429）是请求本身的问题，重试无益；5xx/429 是瞬时的，值得重试
    e.retryable = res.status >= 500 || res.status === 429;
    throw e;
  }
  let json;
  try {
    json = JSON.parse(text);
  } catch {
    throw new Error(`token refresh returned invalid JSON: ${redactSensitive(text.slice(0, 300))}`);
  }

  const str = (o, k) => {
    const v = o && typeof o === "object" ? o[k] : undefined;
    return typeof v === "string" && v.trim() ? v.trim() : undefined;
  };
  const warnings = [];

  // 先把两个字段都取出来（都不抛错），再按"哪一类缺失"决定走哪条留证路径。
  // 顺序很重要：C2 指出「有 RT 无 AT」时新 RT 不能随响应一起蒸发。
  const accessToken = str(json, "access_token");
  const newRefreshToken = str(json, "refresh_token");

  if (!newRefreshToken) {
    // S1：没有新的 refresh_token → 绝不沿用旧值（旧值此刻已作废）
    const e = new Error(
      "OAuth response contained no refresh_token. The server may already have rotated the old one, " +
        "so the previous refresh_token must NOT be written back. The session needs a fresh `mcode login`."
    );
    e.stage = "oauth";
    e.fatalNoRefreshToken = true;
    e.accessToken = accessToken; // 供调用方留证
    // 新 AT 的有效期：能算出来就带上，消费端据此判断它还能不能用（算不出就 0 = 当已过期）
    const rawExp = json?.expires_in;
    const expSec =
      typeof rawExp === "number" && Number.isFinite(rawExp) && rawExp > 0
        ? rawExp
        : typeof rawExp === "string" && /^\d+$/.test(rawExp.trim())
          ? Number(rawExp)
          : 0;
    e.expiresAtMs = expSec > 0 ? Date.now() + expSec * 1000 : 0;
    throw e;
  }
  if (newRefreshToken === record.refreshToken) {
    // 服务端没轮换 = 旧 RT 仍可用，这是好消息，不该当成致命
    warnings.push("response refresh_token equals the previous one (server did not rotate)");
  }

  if (!accessToken) {
    // C2：有 RT 无 AT → 新 RT 必须留证，否则它随响应一起丢了
    const e = new Error(
      "OAuth response contained a refresh_token but no access_token. The new refresh_token must be " +
        "preserved or the session is lost — run `mcode login` to restore it."
    );
    e.stage = "oauth";
    e.fatalNoAccessToken = true;
    e.refreshTokenRecovered = newRefreshToken;
    throw e;
  }

  const tokenTypeRaw = str(json, "token_type");
  if (!tokenTypeRaw) warnings.push("response had no token_type, assumed Bearer");
  else if (tokenTypeRaw.toLowerCase() !== "bearer") warnings.push(`unexpected token_type "${tokenTypeRaw}"`);

  let expiresIn;
  const rawExpires = json?.expires_in;
  if (typeof rawExpires === "number" && Number.isFinite(rawExpires) && rawExpires > 0) expiresIn = rawExpires;
  else if (typeof rawExpires === "string" && /^\d+$/.test(rawExpires.trim()) && Number(rawExpires) > 0)
    expiresIn = Number(rawExpires);
  let expiresAtEstimated = false;
  if (!expiresIn) {
    // 保守取值：宁可让 store 里的有效期偏短（早一点去续期），也不要偏长（到期后突然 401）
    expiresIn = 900;
    expiresAtEstimated = true;
    warnings.push("response had no valid expires_in, assumed a conservative 900s");
  }

  // scope：响应 scope → JWT payload 的 scope/scp（上游 se() 的取值链）
  const jwtPayload = decodeJwtPayload(accessToken);
  const rawScope = json?.scope ?? jwtPayload?.scope ?? jwtPayload?.scp;
  let scopeList;
  if (typeof rawScope === "string") scopeList = rawScope.split(/\s+/u).filter(Boolean);
  else if (Array.isArray(rawScope) && rawScope.every((x) => typeof x === "string")) scopeList = rawScope;
  else scopeList = [];
  let scopeMismatch = false;
  if (!scopeList.length) {
    scopeList = Array.isArray(record.scopes) && record.scopes.length ? record.scopes : [...SCOPES];
    warnings.push(`response had no usable scope, kept ${JSON.stringify(scopeList)}`);
  } else if (!scopeList.includes(SCOPES[0])) {
    scopeMismatch = true;
    warnings.push(`refreshed scope ${JSON.stringify(scopeList)} does not include "${SCOPES[0]}"`);
  }

  if (warnings.length) log(`warn: token response deviations: ${warnings.join("; ")}`);

  return {
    accessToken,
    refreshToken: newRefreshToken,
    tokenType: "Bearer",
    expiresAtMs: Date.now() + expiresIn * 1000,
    expiresAtEstimated,
    scope: scopeList,
    scopeMismatch,
    warnings,
  };
}

// ================= 签到请求 =================

function buildRequest(endpoint, { token, realUserID, body, nowMs, region }) {
  const lang = region === "cn" ? "zh" : "en";
  const u = new URL(endpoint);
  u.search = new URLSearchParams({
    device_platform: "web",
    biz_id: "3",
    app_id: "3001",
    version_code: "22201",
    is_desktop: "1",
    desktop_version: appVersion().version.trim(),
    unix: String(nowMs),
    timezone_offset: String(new Date().getTimezoneOffset() * -60),
    sys_language: lang,
    lang,
    device_id: "0",
    os_name: process.platform,
    browser_name: "mcode",
    user_id: String(realUserID).trim(),
    client: "mcode",
  }).toString();

  const bodyText = body ?? "";        // GET 时为空
  const sigSeed = body ?? "{}";       // GET 时用 "{}"（与上游 tS 一致）
  const ts = Math.floor(nowMs / 1000);
  const signedPath = `${u.pathname}${u.search}`;

  return {
    url: u,
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
      "User-Agent": "MiniMaxCode",
      Authorization: `Bearer ${token}`,
      yy: md5(`${encodeURIComponent(signedPath)}_${sigSeed}${md5(String(nowMs))}ooui`),
      "x-timestamp": String(ts),
      "x-signature": md5(`${ts}I*7Cf%WZ#S&%1RlZJ&C2${bodyText}`),
    },
    body: body,
  };
}

/** L10：找不到就标 known=false，别让 "0.0.0" 冒充真实版本混进签名请求 */
function appVersion() {
  const candidates = [
    path.join(HOME, "..", "AppData", "Roaming", "npm", "node_modules", "@minimax-ai", "code", "package.json"),
    "D:/Program Files/MiniMax/MiniMax Code/resources/app.asar.unpacked/node_modules/@minimax-ai/code/package.json",
    path.join(process.execPath, "..", "..", "..", "node_modules", "@minimax-ai", "code", "package.json"),
  ];
  for (const c of candidates) {
    const j = readJsonSafe(path.resolve(c));
    if (j?.version) return { version: String(j.version), known: true };
  }
  return { version: "0.0.0", known: false };
}

async function apiCall({ endpoint, method, token, realUserID, region, body, stage = "api" }) {
  const nowMs = Date.now();
  const req = buildRequest(endpoint, { token, realUserID, body, nowMs, region });
  const headers = { ...req.headers };
  if (req.body !== undefined) headers["Content-Length"] = Buffer.byteLength(req.body);
  const res = await httpsRequest(req.url.toString(), {
    method,
    headers,
    body: req.body !== undefined ? req.body : null,
  });
  const text = res.text;
  let json;
  try { json = JSON.parse(text); } catch { json = null; }
  if (res.status < 200 || res.status >= 300) {
    const err = new Error(`HTTP ${res.status}: ${redactSensitive(text.slice(0, 300))}`);
    err.status = res.status;
    err.httpStatus = res.status; // M5：字段名统一，输出层同时读 status / httpStatus
    err.stage = stage;
    // 4xx（除 429）是请求本身的问题，重试无益；5xx/429 是瞬时的，值得重试
    err.retryable = res.status >= 500 || res.status === 429;
    err.json = json;
    throw err;
  }
  const code = json?.base_resp?.status_code;
  if (typeof code === "number" && code !== 0) {
    const e = new Error(json?.base_resp?.status_msg || `base_resp status_code=${code}`);
    e.stage = stage;
    e.retryable = false;
    throw e;
  }
  if (!json || json.data === null || json.data === undefined) {
    const e = new Error("response data is missing");
    e.stage = stage;
    e.retryable = false;
    throw e;
  }
  return json.data;
}

// ================= 面板校验与解析（对齐上游 Zgr / nGi / tGi / rGi） =================

/** 上游 Zgr 的等价校验：不合法的面板直接拒绝，而不是照签 */
function isValidPanel(panel) {
  if (!panel || typeof panel !== "object") return false;
  if (!VALID_SCENE.has(panel.scene)) return false;
  const days = panel.days;
  if (!Array.isArray(days) || days.length !== 7) return false;
  const seen = new Set();
  let claimables = 0;
  let todays = 0;
  for (const d of days) {
    if (!d || typeof d !== "object") return false;
    if (typeof d.day_no !== "number" || !Number.isInteger(d.day_no) || d.day_no < 1 || d.day_no > 7) return false;
    if (seen.has(d.day_no)) return false;
    seen.add(d.day_no);
    if (typeof d.points !== "number" || !Number.isFinite(d.points) || d.points < 0) return false;
    if (typeof d.is_today !== "boolean") return false;
    if (typeof d.status !== "number" || !VALID_DAY_STATUS.has(d.status)) return false;
    if (d.status === DAY_CLAIMABLE) claimables++;
    if (d.is_today) todays++;
  }
  return claimables <= 1 && todays <= 1;
}

function panelInfo(panel) {
  const days = [...(panel?.days ?? [])].sort((a, b) => a.day_no - b.day_no);
  const cycle = days.map((d) => (d.status === DAY_CLAIMED ? "✓" : "·")).join(" ");
  const cycleAscii = days.map((d) => (d.status === DAY_CLAIMED ? "V" : ".")).join(" ");
  const todayIdx = days.findIndex((d) => d.is_today);
  const today = todayIdx >= 0 ? days[todayIdx] : null;
  const todayClaimed = !!(today && today.status === DAY_CLAIMED);
  const claimable = days.some((d) => d.status === DAY_CLAIMABLE);
  // 上游 nGi：今天已领 → 从今天往回数；今天可领 → 从昨天往回数
  let streak = 0;
  if (todayIdx >= 0) {
    let i = today.status === DAY_CLAIMED ? todayIdx : today.status === DAY_CLAIMABLE ? todayIdx - 1 : -1;
    for (; i >= 0 && days[i]?.status === DAY_CLAIMED; i--) streak++;
  }
  return { days, cycle, cycleAscii, today, todayClaimed, claimable, streak };
}

/** 上游 iGi 的等价校验：claim 响应必须合法 */
function isValidClaim(claim) {
  if (!claim || typeof claim !== "object") return false;
  if (typeof claim.claim_id !== "string" || claim.claim_id.length === 0) return false;
  if (!VALID_CLAIM_RESULT.has(claim.claim_result)) return false;
  if (!Number.isInteger(claim.day_no) || claim.day_no < 1 || claim.day_no > 7) return false;
  if (typeof claim.points !== "number" || !Number.isFinite(claim.points) || claim.points < 0) return false;
  if (typeof claim.expire_at_ms !== "number" || !Number.isFinite(claim.expire_at_ms)) return false;
  return true;
}

// ================= 进程探测 =================

/**
 * 是否有持有同一份凭据的客户端在运行。
 *
 * ⚠️ 匹配必须同时覆盖正斜杠和反斜杠：Windows 上真实命令行是
 * `C:\Users\...\node_modules\@minimax-ai\code\cli.js`，
 * 只写 `-like '*@minimax-ai/code*'` 会漏掉 mcode CLI（已实测复现）。
 *
 * 误判成「没运行」→ 轮换共享 token → 踢用户下线（严重）；
 * 误判成「在运行」→ 只是签不到（轻微）。所以失败时一律按「在运行」处理。
 */
function isMCodeRunning() {
  try {
    const ps =
      `Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | ` +
      `Where-Object { $_.ProcessId -ne ${process.pid} -and ( ` +
      `$_.Name -like '*MiniMax*' -or $_.Name -like 'mcode*' -or ` +
      `($_.CommandLine -and ( ` +
      `$_.CommandLine -like '*@minimax-ai\\code*' -or ` +
      `$_.CommandLine -like '*@minimax-ai/code*' -or ` +
      `$_.CommandLine -like '*\\@minimax-ai\\*' -or ` +
      `$_.CommandLine -like '*mcode-tools*' ` +
      `))) } | Measure-Object | Select-Object -ExpandProperty Count`;
    const out = execFileSync("powershell", ["-NoProfile", "-NonInteractive", "-Command", ps], {
      encoding: "utf8",
      timeout: 60000,
      windowsHide: true,
    });
    return Number(String(out).trim()) > 0;
  } catch {
    // 探测失败时保守：当作「在运行」→ 宁可不签也不轮换
    log("warn: MCode process detection failed, treating as RUNNING (will not rotate token)");
    return true;
  }
}

// ================= 主流程 =================

/**
 * 等 MCode 自己把 token 刷新好（它在 401 后会续期并回写 store）。
 * 判据是「accessToken 变了」，不能看 expiresAtMs —— 被顶掉的旧记录 expiresAtMs 仍是未来值。
 */
async function waitForExternalRefresh(authDir, timeoutMs, previousToken) {
  const deadline = Date.now() + timeoutMs;
  let lastSeen = fingerprint(previousToken);
  while (Date.now() < deadline) {
    // L8：sleep 不能超过剩余时间，否则实际超时最多超出一个轮询周期
    const remain = deadline - Date.now();
    if (remain <= 0) break;
    await new Promise((r) => setTimeout(r, Math.min(5000, remain)));
    const { record } = loadStore(authDir);
    const tok = record?.accessToken ?? "";
    const fp = fingerprint(tok);
    if (fp !== lastSeen) {
      log(`store token changed (fp=${fp}), expiresAtMs=${record?.expiresAtMs}`);
      lastSeen = fp;
    }
    if (tok && tok !== previousToken) {
      const exp = record?.expiresAtMs ?? 0;
      if (!exp || Date.now() < exp + GRACE_MS) {
        log(`external refresh observed, new expiresAtMs=${exp}`);
        return record;
      }
      log("new token still expired, keep waiting");
    }
  }
  return null;
}

/**
 * 白名单式重建凭据对象（与上游 ae() 同构，chunk-77VGHMFO.js）：
 * 上游的 ae() 是**从零重建**，不是把旧记录展开 —— 展开会把旧记录里的陈旧字段
 * （idToken / deviceCode 之类）一起带进新凭据。本机真实 store 的字段集恰好就是这个白名单。
 *
 * @param base    旧凭据（提供 loginEpoch / subject / accountId 等沿用字段）
 * @param overrides 要覆盖的字段；`refreshToken: null` 表示**显式清空**（旧值已作废）
 */
function rebuildCredential(base, overrides = {}) {
  const b = base ?? {};
  return {
    schemaVersion: 1,
    accessToken: overrides.accessToken !== undefined ? overrides.accessToken : b.accessToken ?? null,
    refreshToken: overrides.refreshToken !== undefined ? overrides.refreshToken : b.refreshToken ?? null,
    tokenType: overrides.tokenType ?? b.tokenType ?? "Bearer",
    clientId: CLIENT_ID,
    scopes: overrides.scopes ?? b.scopes ?? [...SCOPES],
    audience: overrides.audience ?? b.audience ?? AUDIENCE,
    expiresAtMs: overrides.expiresAtMs ?? b.expiresAtMs ?? 0,
    generation: overrides.generation ?? b.generation ?? 0,
    loginEpoch: b.loginEpoch, // 上游沿用上一轮的 loginEpoch
    ...(b.subject ? { subject: b.subject } : {}),
    ...(b.accountId ? { accountId: b.accountId } : {}),
  };
}

/**
 * 上游 k()/v() 的字段集，逐字段对齐（chunk-77VGHMFO.js）。
 * 上游 state 的合法状态：anonymous/authorizing/authenticated/refreshing/
 * scope_upgrade_required/logging_out/logout_pending/expired/error
 */
function buildAuthState({ status, generation, expiresAtMs, scopes, buildEnv, region, audience }) {
  return JSON.stringify(
    {
      schemaVersion: 2,
      status,
      storeKind: "file",
      clientId: CLIENT_ID,
      scopes: Array.isArray(scopes) ? scopes : [...SCOPES],
      audience: audience ?? AUDIENCE,
      buildEnv,
      region,
      generation,
      expiresAtMs,
    },
    null,
    2
  );
}

/**
 * 在确认 MCode 未运行的前提下，续期并安全地写回凭据库。
 *
 * 提交顺序与上游 refreshCredential() 逐项对齐（chunk-77VGHMFO.js）：
 *   1) state 先标成 "refreshing"（generation 不变）—— 让桌面端走自愈分支而不是 error 分支；
 *   2) 调 OAuth 换 token，失败则 state 落回 "expired"（generation 不变）并抛错；
 *   3) newGeneration = max(state.generation, credential.generation) + 1；
 *   4) 先写 auth.json（保住新 token），再写 auth-state.json（对齐 generation）。
 *
 * 全程持上游同一把锁（<authDir>/auth.lock.lock）并在锁内重读，与上游同构。
 *
 * ⚠️ 第 4 步的顺序是硬约束：服务端轮换后旧 refresh_token 立刻作废，
 * 绝不能为了「两文件 generation 一致」而回滚 auth.json（那等于把作废 token 写回去）。
 *
 * ⚠️ 失败时的 state 绝不能回滚成 "authenticated" —— 那是骗桌面端说"你没事"，
 * 而事实是 store 里的 refresh_token 已经作废。保持 "expired" 才是诚实的中间态。
 */
async function refreshAndPersist({ authDir, region, buildEnv }) {
  // 写回前再探一次进程（收窄 TOCTOU 窗口）
  if (isMCodeRunning()) {
    const e = new Error(
      "MiniMax Code started while preparing to refresh — refusing to rotate the shared refresh_token."
    );
    e.retryable = true;
    throw e;
  }
  const lockPath = path.join(authDir, "auth.lock");
  const pendingPath = path.join(authDir, "auth.json.pending");
  try {
    return await withAuthLock(lockPath, async (guard) => {
    try {
    // 锁内重读：用的是最新快照，绝不用旧快照覆盖桌面端刚写入的凭据
    const fresh = loadStore(authDir);
    let rec = fresh.record;
    // C9：generation 一律数值化 —— 字符串 "12" 若被当成 0，比较方向会翻转
    const numGen = (v) => {
      const n = Number(v);
      return Number.isFinite(n) && n >= 0 ? Math.floor(n) : 0;
    };
    let stateGen = numGen(fresh.state?.generation);
    let credGen = numGen(rec?.generation);
    const authJsonPath = path.join(authDir, "auth.json");
    const statePath = path.join(authDir, "auth-state.json");

    // ---- 4.4：generation 非法时必须拒绝轮换，绝不当成 0 ----
    // 若 store 与 state 的 generation 都是非法值，numGen 会把两边都归零 → 「看起来相等」
    // → nextGeneration=1 → 把 generation 写小了 → 上游 getStatus() 判 "error" → 强制重登。
    // 正确处置：认不出来就不动，宁可本次不签到，也不要写坏 generation。
    const genUnparsable = (v) =>
      v !== undefined && v !== null && v !== "" && !Number.isFinite(Number(v));
    if (genUnparsable(fresh.state?.generation) || genUnparsable(rec?.generation)) {
      const e = new Error(
        `credential generation is not a number (state=${JSON.stringify(fresh.state?.generation)}, ` +
          `credential=${JSON.stringify(rec?.generation)}) — refusing to rotate to avoid writing a regressed generation`
      );
      e.stage = "precondition";
      e.retryable = false;
      throw e;
    }

    // 上游 k()/v() 的字段集，逐字段对齐
    const buildState = (status, generation, expiresAtMs, scopes) =>
      buildAuthState({
        status,
        generation,
        expiresAtMs,
        scopes: Array.isArray(scopes) ? scopes : Array.isArray(rec?.scopes) ? rec.scopes : SCOPES,
        buildEnv,
        region,
        audience: rec?.audience ?? AUDIENCE,
      });
    const prevExpires = fresh.state?.expiresAtMs ?? rec?.expiresAtMs ?? 0;

    // ---- M2 前置校验：上游 readUsableCredential 的同款规则 ----
    // ⚠️ 这两道护栏必须排在「采纳 pending」**之前**（第五轮 S2）：
    //    原来 pending 恢复分支在护栏之前就采纳并写库 →
    //    ① status=logging_out（用户刚注销）→ 复活已注销会话；
    //    ② state.generation > credential.generation（外来写入）→ 把代数写倒退。
    // 少了这两条，脚本可能在「用户刚注销」或「别的进程正在写」时把会话复活 / 把状态写坏。
    const st = fresh.state?.status;
    const stateMissing = st === undefined || st === null || st === "";
    // D8：state 文件缺失时，只有「pending 能重建它」才允许继续 ——
    // 否则桌面端那边 getStatus() 本来就已经是 error 了，我们不该再动凭据。
    const pendingRaw = stateMissing ? pendingCredential(authDir, fresh.recordKey) : null;
    if (stateMissing) {
      if (!pendingRaw) {
        const e = new Error(
          "auth-state.json is missing and there is no pending credential to rebuild it — run `mcode login`"
        );
        e.stage = "precondition";
        e.retryable = false;
        throw e;
      }
      log("auth-state.json is missing — it will be rebuilt from the pending credential");
    } else if (!ROTATABLE_STATUS.has(st)) {
      const e = new Error(
        `credential state is "${st}" — refusing to rotate (allowed: ${[...ROTATABLE_STATUS].join(" / ")})`
      );
      e.stage = "precondition";
      e.retryable = false;
      throw e;
    }
    // store 里**没有**记录时不做代数比较（那是「凭据丢了」的场景，只能靠 pending 恢复）
    if (!stateMissing && fresh.record && stateGen !== credGen) {
      if (credGen > stateGen && (st === "refreshing" || st === "authorizing")) {
        // 上次提交被打断在「写完 auth.json、还没写 auth-state.json」之间 ——
        // 上游的 recoverInterruptedCredentialCommit() 正是处理这个中间态的（且只在
        // status ∈ {authorizing, refreshing} 时处理）。我们与它同构。
        // 注意：status 是 authenticated/expired 时出现这个不等式 = **外来写入**
        // （别的工具/备份恢复/换账号），上游对此一律判 "error"，我们也不能自愈抹平。
        const healScopes = Array.isArray(rec.scopes) ? rec.scopes : [...SCOPES];
        const healScopeOk = healScopes.includes(SCOPES[0]); // 上游同款 scope 校验
        log(`healing interrupted credential commit (state.generation=${stateGen} < credential.generation=${credGen})`);
        // 4.2：写 state 之前必须当场确认锁还在我们手里（失锁后写 = 覆盖对方刚写的状态）
        guard.assertHeld();
        await atomicWriteFileWithRetry(
          statePath,
          buildState(healScopeOk ? "authenticated" : "scope_upgrade_required", credGen, rec.expiresAtMs, healScopes)
        );
        stateGen = credGen;
      } else {
        const e = new Error(
          `credential generation mismatch (state=${stateGen}, credential=${credGen}, status=${st}) — refusing to rotate`
        );
        e.stage = "precondition";
        throw e;
      }
    }

    // ---- C7：pending 侧路文件必须能被自动消费 ----
    // pending 是**我们上一次运行留下的完整产物**（一次成功轮换，但 auth.json 写失败）。
    // 正确处置不是"把它当轮换输入"（那会与 generation 校验互斥 → 消费路径 100% 走不通），
    // 而是"把它写回 auth.json + 把 state 对齐" = 恢复凭据。
    // 恢复之后：AT 仍有效就直接用（连 OAuth 都不用打）；AT 过期才用 pending 里的 RT 正常轮换。
    const pendingAdopted = (() => {
      try {
        const pendingStore = readJsonSafe(pendingPath);
        const pRec = pendingStore?.records?.[fresh.recordKey];
        if (!pRec) return null;
        if (genUnparsable(pRec.generation)) return null; // 非法代数 → 不采纳（不靠巧合）
        const pGen = numGen(pRec.generation);
        // S2：必须同时比过 state 和 credential 两道代数 ——
        // 只比 credential 会在「state 比 credential 新」（外来写入）时把 state 代数写倒退。
        if (pGen <= credGen || pGen <= stateGen) return null;
        if (!pRec.refreshToken && !pRec.accessToken) return null;
        return { rec: pRec, gen: pGen, store: pendingStore };
      } catch {}
      return null;
    })();
    if (pendingAdopted) {
      const p = pendingAdopted;
      const pExpires = p.rec.expiresAtMs ?? 0;
      const pScopes = Array.isArray(p.rec.scopes) ? p.rec.scopes : [...SCOPES];
      const pScopeOk = pScopes.includes(SCOPES[0]);
      // S10：与主路径 usable() 同口径（都带 GRACE_MS），别在这里判活、主路径判死
      const pAtUsable = !!p.rec.accessToken && Date.now() < pExpires + GRACE_MS;
      const pHasRt = !!p.rec.refreshToken;

      // ---- S5：只有 access_token、没有 refresh_token 的 pending ----
      // 服务端已轮换却没回 RT（响应形状异常）时，旧 RT 此刻已作废，而新 AT 还有效。
      // 这种 pending **不能**写回 store（写回 null RT 只会把桌面端弄得更糟），
      // 只能只读地拿它的 AT 完成今天的签到，并明确提示需要重新登录。
      if (!pHasRt) {
        if (!pAtUsable) {
          const e = new Error(
            "the pending credential carries no refresh_token and its access_token has expired — " +
              "the session must be restored with `mcode login`"
          );
          e.stage = "precondition";
          e.retryable = false;
          throw e;
        }
        log("the pending credential only carries an access token — using it read-only, no store write");
        return {
          token: p.rec.accessToken,
          expiresAtMs: pExpires,
          generation: p.gen,
          stateStatus: "expired",
          warnings: [
            "the session lost its refresh_token; signed in with the pending access token only — run `mcode login` to restore the session",
          ],
          scopeMismatch: !pScopeOk,
          expiresAtEstimated: false,
          recovered: true,
          persisted: false, // D5：一个字都没写库，别让监控误判成「已落盘」
        };
      }

      const pStateStatus = !pScopeOk ? "scope_upgrade_required" : pAtUsable ? "authenticated" : "expired";
      log(`recovering a pending credential (generation ${credGen} -> ${p.gen})`);
      // ---- S1：严格按上游的提交顺序 ----
      // 上游 refreshCredential()：state=refreshing(代数不变) → 写凭据 → 写 state。
      // 中间态是 status=refreshing 时被杀掉，上游走 recoverInterruptedCredentialCommit() 自愈；
      // 若先写凭据后写 state 且没有 refreshing 标记，中间态会退化成 status:"error" → 强制重登。
      guard.assertHeld();
      await atomicWriteFileWithRetry(statePath, buildState("refreshing", stateGen, prevExpires));
      guard.assertHeld();
      // ② 把 pending 的凭据写回 auth.json —— **合并写**（S4），
      //    别用 pending 时刻的整份快照，否则这之后新增的其它记录会被静默删掉。
      const mergedStore = {
        ...fresh.store,
        schemaVersion: 1,
        records: {
          ...(fresh.store?.records ?? {}),
          [fresh.recordKey]: rebuildCredential(p.rec, { generation: p.gen }),
        },
      };
      await writeAuthJson(authJsonPath, mergedStore);
      // ③ 把 state 对齐到 pending 的 generation
      //    D1：写之前必须确认（a）锁还在我们手里（b）store 里的凭据仍然是我们刚写的那份。
      //    别人若在间隙里提交了更高代数的凭据，我们绝不能把 state 写回旧代数 ——
      //    上游 getStatus() 看到「代数不等 + status 非 refreshing」会判 error → 强制重登。
      //    这种情况就**不写 state**（让上游的 recoverInterruptedCredentialCommit 自愈）。
      guard.assertHeld();
      const afterCred = loadStore(authDir);
      if (numGen(afterCred.record?.generation) !== p.gen) {
        log(
          `warn: the credential generation changed while restoring the pending credential ` +
            `(expected ${p.gen}, now ${numGen(afterCred.record?.generation)}) — leaving auth-state.json untouched (upstream will heal it)`
        );
      } else {
        await atomicWriteFileWithRetry(
          statePath,
          buildAuthState({
            status: pStateStatus,
            generation: p.gen,
            expiresAtMs: pExpires,
            scopes: pScopes,
            buildEnv,
            region,
            audience: p.rec.audience ?? AUDIENCE,
          })
        );
      }
      // ④ pending 已被消费
      try { fs.unlinkSync(pendingPath); } catch (e) { log(`warn: could not delete the pending sidecar: ${e?.message ?? e}`); }
      rec = p.rec;
      stateGen = p.gen;
      credGen = p.gen;
      // ⑤ AT 仍然有效 → 直接用，根本不需要再打 OAuth（连一次 RT 轮换都省了）
      if (pAtUsable) {
        log("the recovered access token is still valid — no OAuth round trip needed");
        return {
          token: p.rec.accessToken,
          expiresAtMs: pExpires,
          generation: p.gen,
          stateStatus: pStateStatus,
          warnings: ["recovered a pending credential left by a previously failed write"],
          scopeMismatch: !pScopeOk,
          expiresAtEstimated: false,
          recovered: true,
        };
      }
      // ⑥ AT 已过期 → 继续用 pending 里的 RT 正常轮换（下面走标准流程）
    }

    if (!rec?.refreshToken) throw new Error("auth store lost its refresh token");

    // M2 的两道护栏（状态 / 代数）已上移到「采纳 pending」之前 —— 见上方注释。

    const nextGeneration = Math.max(stateGen, credGen) + 1;

    // ---- C3：失败路径写 state 前，必须在锁内重读凭据并取更大的 generation ----
    // 否则可能把 generation 写小 → 上游 getStatus 判 "error" → 强制重新登录。
    const currentCredGen = () => {
      try {
        const g = Number(loadStore(authDir).record?.generation);
        return Number.isFinite(g) ? g : 0;
      } catch {
        return 0;
      }
    };
    const writeExpiredState = async () => {
      const g = Math.max(stateGen, currentCredGen());
      try {
        // 4.2：失锁后不许再写 state
        guard.assertHeld();
        await atomicWriteFileWithRetry(statePath, buildState("expired", g, prevExpires));
      } catch (e) {
        // S7：别把「失锁所以不写」和「磁盘写失败」混成同一个静默 —— 事后要能分辨
        log(`warn: could not write the expired auth state: ${e?.message ?? e}`);
      }
    };

    // 1) 先标记 refreshing
    try {
      // 4.2：失锁后不许再写 state
      guard.assertHeld();
      await atomicWriteFileWithRetry(statePath, buildState("refreshing", stateGen, prevExpires));
    } catch (e) {
      throw new Error(`could not mark auth state as refreshing: ${e?.message ?? e}`);
    }

    // 2) 换 token
    let refreshed;
    try {
      refreshed = await refreshAccessToken({
        record: rec,
        region,
        endpoint: oauthTokenEndpoint(region, buildEnv),
      });
    } catch (e) {
      if (e.fatalNoAccessToken) {
        // C2：响应里有**新的 refresh_token** 却没有 access_token。
        // 新 RT 必须进 store —— 否则它随响应一起蒸发 = 会话报废。
        // 凭据用「新 RT + 旧 AT」构成（旧 AT 可能仍然有效），generation 对齐。
        const recoveredCred = rebuildCredential(rec, {
          refreshToken: e.refreshTokenRecovered,
          expiresAtMs: rec.expiresAtMs ?? 0,
          generation: nextGeneration,
        });
        const recoveredStore = {
          ...fresh.store,
          schemaVersion: 1,
          records: { ...fresh.store.records, [fresh.recordKey]: recoveredCred },
        };
        try {
          // 4.2：失锁后不许再写凭据（会覆盖对方刚写的新凭据）
          guard.assertHeld();
          await atomicWriteFileWithRetry(pendingPath, JSON.stringify(recoveredStore, null, 2)); // 先保底
          await writeAuthJson(authJsonPath, recoveredStore);
          // D1：写 state 前同样要确认锁还在我们手里，且 store 里的凭据仍是我们刚写的那份
          guard.assertHeld();
          const afterCred = loadStore(authDir);
          if (numGen(afterCred.record?.generation) !== nextGeneration) {
            log(
              `warn: the credential generation changed while persisting the recovered refresh_token ` +
                `(expected ${nextGeneration}, now ${numGen(afterCred.record?.generation)}) — leaving auth-state.json untouched`
            );
          } else {
            await atomicWriteFileWithRetry(
              statePath,
              buildState("expired", nextGeneration, rec.expiresAtMs ?? 0, rec.scopes)
            );
          }
          try { fs.unlinkSync(pendingPath); } catch (e) { log(`warn: could not delete the pending sidecar: ${e?.message ?? e}`); }
          e.recoveredCredential = true;
        } catch (e2) {
          log(`warn: could not persist the recovered refresh_token: ${e2?.message ?? e2}`);
        }
        e.stage = e.stage ?? "oauth";
        e.fatal = true;
        throw e;
      }
      if (e.fatalNoRefreshToken) {
        // S1：服务端可能已轮换，但没把新的 refresh_token 返回给我。
        // 旧 RT 此刻已作废 —— 绝不能写回 store。
        // S5：留证必须是**可消费的 store 形状**（records[key]）——
        //    原来的诊断形状 {note, accessToken, ...} 消费端根本认不出来 → 永远不会被消费，
        //    还会在磁盘上永久留一个明文 bearer 文件。
        const recoveredStore = {
          ...fresh.store,
          schemaVersion: 1,
          records: {
            ...(fresh.store?.records ?? {}),
            [fresh.recordKey]: rebuildCredential(rec, {
              accessToken: e.accessToken ?? null,
              refreshToken: null, // 服务端已轮换：旧 RT 此刻已作废，绝不能沿用
              expiresAtMs: e.expiresAtMs ?? 0,
              generation: nextGeneration,
            }),
          },
        };
        try {
          await atomicWriteFileWithRetry(pendingPath, JSON.stringify(recoveredStore, null, 2));
        } catch (e2) {
          log(`warn: could not write the pending sidecar: ${e2?.message ?? e2}`);
        }
        await writeExpiredState();
        e.stage = e.stage ?? "oauth";
        e.fatal = true;
        throw e;
      }
      // 失败：落回 expired（generation 取锁内重读到的最大值），别让桌面端卡在 refreshing
      await writeExpiredState();
      throw e;
    }

    // 3) 组装新凭据（白名单式，与上游 ae() 同构）
    // S9：上游是**从零重建**凭据对象，不是 `...rec` 展开 —— 否则会把上一轮的陈旧字段
    //（idToken / deviceCode 之类）一起带下去。
    const nextCred = rebuildCredential(rec, {
      accessToken: refreshed.accessToken,
      refreshToken: refreshed.refreshToken,
      tokenType: refreshed.tokenType ?? rec.tokenType ?? "Bearer",
      scopes: Array.isArray(refreshed.scope) ? refreshed.scope : rec.scopes ?? SCOPES,
      audience: rec.audience ?? AUDIENCE,
      expiresAtMs: refreshed.expiresAtMs,
      generation: nextGeneration,
    });
    const nextStore = {
      ...fresh.store,
      schemaVersion: 1,
      records: { ...fresh.store.records, [fresh.recordKey]: nextCred },
    };

    // 3b) 旁路落盘：先把新凭据写进 auth.json.pending，再写 auth.json，成功后删 pending。
    //     这样即使 auth.json 的 rename 连续失败，新 refresh_token 也不会丢。
    try {
      await atomicWriteFileWithRetry(pendingPath, JSON.stringify(nextStore, null, 2));
    } catch (e) {
      log(`warn: could not write the pending sidecar: ${e?.message ?? e}`);
    }

    // 4a) 先写 auth.json —— 新 refresh_token 必须优先保住（上游同样是 credential 在前、state 在后）
    // C4：写之前先确认锁还在我们手里 —— 失锁后继续写会覆盖对方刚写的新凭据。
    // S3：这一写失败 = 库里留下死 RT = 桌面端下次启动 401 → 用户被踢。所以预算拉长 + 兜底覆盖写。
    guard.assertHeld();
    try {
      // D4：三处写 auth.json 统一走 writeAuthJson（同一套预算 + 兜底覆盖写 + 回读校验）
      await writeAuthJson(authJsonPath, nextStore);
    } catch (e) {
      // 写不进去：store 里仍是**已作废**的旧 refresh_token。
      // 绝不能把 state 回滚成 "authenticated"（那是撒谎）—— 诚实标成 expired。
      await writeExpiredState();
      const e2 = new Error(
        `could not persist refreshed credentials: ${e?.message ?? e}. ` +
          `The refresh_token in the store is now INVALID — MiniMax Code will get a 401 on its next start. ` +
          `Run \`mcode login\` NOW to restore the session. ` +
          `A copy of the new credential was kept at ${pendingPath}.`
      );
      e2.stage = "persist";
      e2.fatal = true;
      throw e2;
    }

    // 4b) auth.json 写成功了 → pending 可以删
    try { fs.unlinkSync(pendingPath); } catch (e) { log(`warn: could not delete the pending sidecar: ${e?.message ?? e}`); }

    // 4c) 再写 auth-state.json 对齐 generation。
    //     scope 不含 agent.default 时按上游写 scope_upgrade_required（L1）。
    //     失败不致命：状态停在 refreshing + generation 落后，上游能自愈。
    guard.assertHeld();
    const stateStatus = refreshed.scopeMismatch ? "scope_upgrade_required" : "authenticated";
    const nextState = buildState(stateStatus, nextGeneration, refreshed.expiresAtMs, nextCred.scopes);
    try {
      await atomicWriteFileWithRetry(statePath, nextState);
    } catch (e) {
      log(`warn: could not write auth-state.json (${e?.message ?? e}); upstream will heal it on next read`);
    }

    // 4d) 自检：两个文件的 generation 是否真的同步
    try {
      const chk = loadStore(authDir);
      if (chk.record?.generation !== chk.state?.generation) {
        log(`warn: generation mismatch after write (credential=${chk.record?.generation}, state=${chk.state?.generation})`);
      }
    } catch {}

    log(
      `refreshed + persisted (fp=${fingerprint(refreshed.accessToken)}, generation=${nextGeneration}, ` +
        `scopes=${JSON.stringify(nextCred.scopes)}, state=${stateStatus})`
    );
    return {
      token: refreshed.accessToken,
      expiresAtMs: refreshed.expiresAtMs,
      generation: nextGeneration,
      stateStatus,
      warnings: refreshed.warnings ?? [],
      scopeMismatch: !!refreshed.scopeMismatch,
      expiresAtEstimated: !!refreshed.expiresAtEstimated,
    };
    } catch (inner) {
      // C14 兜底（**锁内**）：临界区里若抛了未预期的异常，state 可能停在 "refreshing"。
      // 上游的 recoverInterruptedCredentialCommit 在「credential.generation <= state.generation」时
      // 不会修它 → getStatus 一直返回 "refreshing" → 桌面端可能卡在"刷新中"。
      // 这里把状态诚实地落回 expired（generation 取当前最大值，避免倒退）。
      // 第五轮 S8：这一步必须**在锁内**做 —— 锁外写会覆盖并发提交（桌面端刚写的 authenticated）。
      try {
        const s = loadStore(authDir);
        if (s.state?.status === "refreshing") {
          const sGen = Number(s.state?.generation) || 0;
          const cGen = Number(s.record?.generation) || 0;
          // D6：只有「凭据代数确实比 state 新」才对齐写入 ——
          // 否则写出来的 state 代数与凭据不一致，上游 getStatus() 判 "error" → 强制重登
          //（兜底本意是修复，却可能制造 error）。不写则 state 停在 refreshing，上游能自愈。
          if (cGen > sGen) {
            guard.assertHeld();
            await atomicWriteFileWithRetry(
              statePathOf(authDir),
              buildAuthState({
                status: "expired",
                generation: cGen,
                expiresAtMs: s.state?.expiresAtMs ?? s.record?.expiresAtMs ?? 0,
                scopes: s.record?.scopes,
                buildEnv,
                region,
                audience: s.record?.audience ?? AUDIENCE,
              }),
              { attempts: 3 }
            );
          } else {
            log(
              `warn: leaving the auth state at "refreshing" (credential.generation=${cGen} <= state.generation=${sGen}) — ` +
                `upstream will heal it`
            );
          }
        }
      } catch (e3) {
        // 失锁 / 写失败 → 就这样吧：state 停在 refreshing，上游能自愈
        log(`warn: could not fall the auth state back to expired: ${e3?.message ?? e3}`);
      }
      throw inner;
    }
    });
  } catch (e) {
    throw e;
  }
}

function statePathOf(authDir) {
  return path.join(authDir, "auth-state.json");
}

async function main() {
  const authDir = resolveAuthDir();
  if (!authDir) throw new Error("MiniMax auth store not found — run `mcode login` first.");
  let { store, record, recordKey, region, buildEnv, ambiguous } = loadStore(authDir);
  if (ambiguous) {
    // C11：store 里有多条记录且找不到上游精确键 —— 不能猜，可能轮换到别的账号
    const e = new Error(
      "the auth store contains multiple credential records and the expected upstream key was not found — " +
        "refusing to guess which account to use"
    );
    e.stage = "precondition";
    throw e;
  }
  if (!record?.accessToken) {
    // D3：凭据缺失/损坏时，pending 里可能存着**唯一还活着的 refresh_token** ——
    // 先给恢复流程留个机会，别一上来就要用户重新登录。
    if (!pendingCredential(authDir, recordKey)) {
      throw new Error("no access token in auth store — run `mcode login` first.");
    }
    log("no access token in the auth store, but a pending credential is available -> attempting recovery from it");
  }

  const realUserID = resolveRealUserID(authDir, region, buildEnv);
  if (!realUserID) throw new Error("could not resolve realUserID");

  const origin = AGENT_ORIGIN[region] ?? AGENT_ORIGIN.cn;
  let token = record?.accessToken ?? null;
  let expiresAtMs = record?.expiresAtMs ?? 0;
  let tokenSource = "store";
  let expiresAtEstimated = false;
  let scopeMismatch = false;
  // token 是不是来自「pending 恢复」（= 我们自己上一次运行留下的凭据）
  let tokenRecovered = false;
  // 进程探测结果写进输出，便于事后审计（true/false/null=未知）
  let mcodeRunning = null;
  const detectMCode = () => {
    mcodeRunning = isMCodeRunning();
    return mcodeRunning;
  };
  const warnings = [];

  /**
   * 续期结果的统一处理（两条续期路径共用，避免 401 分支漏做 scope 校验 / 漏传字段）。
   */
  const applyRefreshResult = (fresh) => {
    token = fresh.token;
    expiresAtMs = fresh.expiresAtMs;
    // D5：只读恢复（用 pending 的 AT 签到、一个字都没写库）不能谎报成「已落盘」
    tokenSource = fresh.persisted === false ? "recovered (read-only)" : "refreshed (persisted)";
    if (fresh.warnings?.length) warnings.push(...fresh.warnings);
    expiresAtEstimated = !!fresh.expiresAtEstimated;
    scopeMismatch = !!fresh.scopeMismatch;
    tokenRecovered = !!fresh.recovered;
    if (fresh.scopeMismatch) {
      // 刷新的授权不再含 agent.default —— 桌面端已被要求重新授权，
      // 此时「签到成功」是假绿，必须失败。
      const e = new Error(
        "The refreshed authorization no longer includes the \"agent.default\" scope. " +
          "MiniMax Code must re-authorize before daily check-in can work again."
      );
      e.stage = "oauth";
      e.retryable = false;
      throw e;
    }
  };

  const usable = () => expiresAtMs && Date.now() < expiresAtMs + GRACE_MS;

  // ---- token 有效期处理 ----
  if (!usable()) {
    log(`token expired (expiresAtMs=${expiresAtMs}, fp=${fingerprint(token)})`);
    const running = detectMCode();

    if (running) {
      // MCode 在跑：绝不能碰它的 refresh_token。等它自己续期。
      const waitMs = Number(process.env.MCODE_CHECKIN_WAIT_MS ?? 600000);
      log(`MCode is running -> will NOT rotate shared refresh_token; waiting up to ${waitMs}ms`);
      const updated = await waitForExternalRefresh(authDir, waitMs, token);
      if (!updated) {
        const e = new Error(
          "MiniMax access token is expired and MiniMax Code is running, so this script will not " +
            "rotate its shared refresh_token (doing so forces the app back to the login screen). " +
            "Open MiniMax Code once (it refreshes on demand) and retry."
        );
        e.retryable = true;
        e.stage = "token";
        throw e;
      }
      record = updated;
      token = updated.accessToken;
      expiresAtMs = updated.expiresAtMs ?? 0;
      tokenSource = "store (external refresh)";
    } else if (process.env.MCODE_CHECKIN_PERSIST_REFRESH !== "1") {
      const e = new Error(
        "MiniMax access token is expired and MiniMax Code is not running. " +
          "This script refuses to rotate the shared refresh_token by default " +
          "(writing the shared credential store can push MiniMax Code back to its login screen). " +
          "Run `mcode login` once, or set MCODE_CHECKIN_PERSIST_REFRESH=1 to allow it."
      );
      e.retryable = true;
      e.stage = "token";
      throw e;
    } else {
      log("MCode is not running and MCODE_CHECKIN_PERSIST_REFRESH=1 -> refreshing + persisting");
      const fresh2 = await refreshAndPersist({ authDir, region, buildEnv });
      applyRefreshResult(fresh2);
    }
  }

  // 1) 查状态
  const statusCall = () =>
    apiCall({
      endpoint: `${origin}/minimax-cloud/api/v1/signin/status`,
      method: "GET",
      token,
      realUserID,
      region,
      stage: "status",
    });

  let panel;
  try {
    panel = await statusCall();
  } catch (e) {
    if (e?.status !== 401) throw e;
    log("status call 401, re-reading auth store…");
    const fresh2 = loadStore(authDir);
    if (fresh2.record?.accessToken && fresh2.record.accessToken !== token) {
      log("store now holds a different access token, retrying");
      record = fresh2.record;
      token = record.accessToken;
      expiresAtMs = record.expiresAtMs ?? 0;
      tokenSource = "store (rotated by MCode)";
      panel = await statusCall();
    } else if (detectMCode()) {
      // 401 但 store 没变 → 桌面端可能正在续期，等它（而不是直接进续期分支）
      const waitMs = Number(process.env.MCODE_CHECKIN_WAIT_MS ?? 600000);
      log(`store token rejected but MCode is running -> waiting up to ${waitMs}ms`);
      const updated = await waitForExternalRefresh(authDir, waitMs, token);
      if (!updated) {
        const err = new Error(
          "MiniMax access token in the auth store was rejected (HTTP 401) and MiniMax Code is running, " +
            "so this script will not rotate its shared refresh_token. Open MiniMax Code once and retry."
        );
        err.retryable = true;
        err.stage = "status";
        err.httpStatus = 401;
        throw err;
      }
      record = updated;
      token = updated.accessToken;
      expiresAtMs = updated.expiresAtMs ?? 0;
      tokenSource = "store (external refresh)";
      panel = await statusCall();
    } else {
      // MCode 没在跑 → 重新评估是否需要续期（而不是直接抛原始 401）
      if (process.env.MCODE_CHECKIN_PERSIST_REFRESH === "1") {
        log("401 and MCode is not running -> refreshing + persisting");
        const fresh3 = await refreshAndPersist({ authDir, region, buildEnv });
        applyRefreshResult(fresh3);
        panel = await statusCall();
      } else {
        const err = new Error(
          "MiniMax access token was rejected (HTTP 401) and MiniMax Code is not running. " +
            "Run `mcode login` once, or set MCODE_CHECKIN_PERSIST_REFRESH=1 to allow this script to refresh."
        );
        err.retryable = true;
        err.stage = "status";
        err.httpStatus = 401;
        throw err;
      }
    }
  }

  if (!isValidPanel(panel)) {
    const e = new Error("Invalid sign-in panel (failed upstream Zgr-equivalent validation)");
    e.stage = "status";
    throw e;
  }
  let info = panelInfo(panel);
  log(`status panel: ${JSON.stringify({ cycle: info.cycle, streak: info.streak, todayClaimed: info.todayClaimed, claimable: info.claimable })}`);

  let status;
  let points = null;
  let dayNo = info.today?.day_no ?? null;
  // L9：claim 响应里的 panel 是否有效（无效时输出 panelFresh=false，别让"已领"与面板矛盾）
  let panelFresh = true;

  if (info.todayClaimed) {
    status = "already";
  } else if (dryRun) {
    status = info.claimable ? "claimable" : "unavailable";
  } else if (!info.claimable) {
    status = "unavailable";
  } else {
    // 账号一致性检查（上游 assertCurrentAccount / GQe）：claim 前确认凭据没被换掉
    const before = loadStore(authDir);
    const beforeFp = fingerprint(before.record?.accessToken);
    const curFp = fingerprint(token);
    // tokenRecovered：token 来自我们自己上一次运行留下的 pending（恢复凭据），
    //   这时它与 store 里的旧 AT 本来就不同 —— 不是「账号被换掉」。
    //   账号身份仍然由下面那行 realUserID 检查把关。
    if (before.record?.accessToken && beforeFp !== curFp && !tokenRecovered) {
      const e = new Error("MiniMax account changed during daily check-in. Retry.");
      e.stage = "claim";
      throw e;
    }
    // L3：上游比的是**账号**（realUserID），token 指纹只是附加信号
    const nowUserID = resolveRealUserID(authDir, region, buildEnv);
    if (nowUserID && nowUserID !== realUserID) {
      const e = new Error(
        `MiniMax account changed during daily check-in (realUserID ${realUserID} -> ${nowUserID}). Retry.`
      );
      e.stage = "claim";
      throw e;
    }

    const claim = await apiCall({
      endpoint: `${origin}/minimax-cloud/api/v1/signin/claim`,
      method: "POST",
      token,
      realUserID,
      region,
      body: "{}",
      stage: "claim",
    });
    if (!isValidClaim(claim)) {
      const e = new Error("Invalid sign-in claim response (failed upstream iGi-equivalent validation)");
      e.stage = "claim";
      throw e;
    }
    if (claim.claim_result === RESULT_ALREADY) {
      status = "already";
    } else {
      status = "claimed";
      points = typeof claim.points === "number" ? claim.points : null;
      dayNo = typeof claim.day_no === "number" ? claim.day_no : dayNo;
    }
    // 只有 panel 合法才覆盖，否则保留 GET status 拿到的正确面板
    if (isValidPanel(claim.panel)) {
      info = panelInfo(claim.panel);
    } else {
      panelFresh = false;
      warnings.push("claim response carried no valid panel; kept the panel from the status call");
      log("claim response panel invalid/missing, keeping panel from status call");
    }
  }

  return {
    // L7：unavailable 是正常结果（今天没得领），不该让"非 0 即失败"的消费方天天误报
    ok: status === "claimed" || status === "already" || status === "unavailable",
    status,
    streakDays: info.streak,
    cycle: info.cycle,
    cycleAscii: info.cycleAscii,
    points,
    dayNo,
    todayClaimed: info.todayClaimed,
    panelFresh,
    region,
    buildEnv,
    dryRun,
    tokenSource,
    mcodeRunning,
    desktopVersionKnown: appVersion().known,
    // C13：有效期是猜的时候必须让消费方知道
    expiresAtEstimated,
    scopeMismatch,
    // L2：降级信息必须进 JSON，否则 cron 只看到"成功"，看不到"这次是降级成功的"
    degraded: warnings.length > 0,
    warnings,
  };
}

// ================= 输出 =================

const startedAt = Date.now();

/**
 * 退出码：0=claimed/already/unavailable  1=致命  2=claimable(dry-run 发现可领)  3=可重试
 * L7：unavailable 归入 0 —— 「今天没得领」是正常结果，不是失败。
 */
function exitCodeFor(result) {
  if (result.ok) return 0;
  if (result.status === "claimable") return 2;
  return 1;
}

/**
 * JSON 一律走 stdout（stderr 只放人类可读摘要），
 * 写完等 flush 回调再退出，避免管道场景被截断。
 */
function emit(result, code) {
  const out = { ...result, elapsedMs: Date.now() - startedAt, ts: new Date().toISOString() };
  if (jsonPath) {
    try {
      fs.mkdirSync(path.dirname(jsonPath), { recursive: true });
      atomicWriteFile(jsonPath, JSON.stringify(out, null, 2), 0o644);
    } catch (e) {
      process.stderr.write(`[warn] could not write json: ${e?.message ?? e}\n`);
    }
  }
  const line = JSON.stringify(out) + "\n";
  process.exitCode = code;
  let finished = false;
  // 兜底：万一 stdout 一直不 flush，最多再等 10s。
  // 注意这个 timer **不能 unref** —— unref 后事件循环可能已经空了，
  // 进程会在 flush 回调之前就退出，正好在最需要兜底的时候失效。
  const fallback = setTimeout(() => {
    try { process.exit(code); } catch {}
  }, 10000);
  const done = () => {
    if (finished) return;
    finished = true;
    clearTimeout(fallback);
    try { process.exit(code); } catch {}
  };
  try {
    process.stdout.write(line, done);
  } catch {
    done();
  }
}

main()
  .then((result) => {
    const code = exitCodeFor(result);
    log(`result: ${JSON.stringify({ status: result.status, streakDays: result.streakDays, points: result.points, cycle: result.cycle })}`);
    if (code !== 0) {
      process.stderr.write(`[checkin] status=${result.status} (exit ${code})\n`);
    }
    emit(result, code);
  })
  .catch((e) => {
    const out = {
      ok: false,
      status: "error",
      error: redactSensitive(e?.message || String(e) || "unknown error"),
      // reason：fatal=不可自动恢复 / retryable=稍后重试 / error=其它
      reason: e?.fatal ? "fatal" : e?.retryable ? "retryable" : "error",
      stage: e?.stage ?? "unknown",
      // M5：字段名统一（status 与 httpStatus 兼容读取）
      httpStatus: e?.status ?? e?.httpStatus ?? null,
      retryable: e?.retryable === true,
      degraded: false,
      warnings: [],
      // S6：解析不到凭据目录时返回 null —— 别用 "." 兜底（那会从 cwd 反推出
      // region:"workspace" / buildEnv:".minimax" 之类的垃圾值污染监控）
      region: (() => { try { const d = resolveAuthDir(); return d ? loadStore(d).region : null; } catch { return null; } })(),
      buildEnv: (() => { try { const d = resolveAuthDir(); return d ? loadStore(d).buildEnv : null; } catch { return null; } })(),
      tokenSource: "unknown",
      dryRun,
    };
    log(`error: ${out.error}`);
    process.stderr.write(`[checkin] ${out.error}\n`);
    emit(out, out.retryable ? 3 : 1);
  });
