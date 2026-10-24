/**
 * 进程探测的定向破坏测试 —— 「mcode-checkin-direct.mjs」的安全护栏回归验证。
 *
 * 用法：
 *   node tools/test-process-detection.mjs ../mcode-checkin-direct.mjs
 *   node tools/test-process-detection.mjs path/to/mcode-checkin-direct.mjs
 *
 * 背景（为什么这个文件存在）：
 *   进程探测 `isMCodeRunning()` 决定「桌面端是否在运行」。判断错的方向是**致命的**：
 *     · 误判「在跑」  → 自续期写回分支永不可达 → 无人值守签到必然失败（空等后 exit 3）；
 *     · 误判「没在跑」→ 去轮换共享 refresh_token → 桌面端拿到已作废的 RT → **用户被踢回登录页**。
 *
 *   历史事故：原实现只排除了 node 自身 PID，排不掉探测命令自己派生的 powershell.exe
 *   （它的命令行里含 `@minimax-ai\code` 字面量）⇒ 探测恒为「在跑」⇒ 写回路径形同虚设。
 *   修复用随机 marker 精确排除自匹配。
 *
 *   修复过程中又踩到一个更隐蔽的坑：**复核者建议的「按父进程 PID 排除」会造成真实漏报** ——
 *   任何恰好是脚本 node 直接子进程的匹配进程会被静默丢弃 ⇒ 误判「没在跑」⇒ 踢人下线。
 *   ⇒ 两条不变量必须一起验，且 P2 是防这种「方向相反的新缺陷」的护栏。
 *
 * 被测对象 = 从**真实脚本源码**里按大括号配对抽取的 isMCodeRunning()，
 * 只做两处最小改写：① 计数量改为输出 PID 列表；② 返回值附带 PID 集合与 marker。
 *    ⇒ 测的永远是真实实现，不是重写版。脚本形态变了会**报错退出**（不会静默通过）。
 *
 * 判定按 **PID 集合成员**而不是总数 —— 环境进程数本身会抖动（Electron 的 renderer
 * 进程时增时减），比总数会假红。
 */

import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import crypto from "node:crypto";
import { execFileSync, spawn } from "node:child_process";
import { pathToFileURL } from "node:url";

const SCRIPT = process.argv[2];
if (!SCRIPT) {
  console.error("usage: node tools/test-process-detection.mjs <path-to-mcode-checkin-direct.mjs>");
  process.exit(2);
}
const src = fs.readFileSync(SCRIPT, "utf8");

/** 按大括号配对抽取函数源码（该函数内无含 { } 的字面量） */
function extractFunction(text, name) {
  const start = text.indexOf(`function ${name}(`);
  if (start < 0) throw new Error(`function ${name} not found`);
  const bodyStart = text.indexOf("{", start);
  let depth = 0;
  for (let i = bodyStart; i < text.length; i++) {
    const ch = text[i];
    if (ch === "{") depth++;
    else if (ch === "}") {
      depth--;
      if (depth === 0) return text.slice(start, i + 1);
    }
  }
  throw new Error(`unbalanced braces for ${name}`);
}

const fnSrc = extractFunction(src, "isMCodeRunning");

// 改写 ①：让 PS 查询输出匹配的 PID 列表（不再只输出计数）
const COUNT_TAIL = "| Measure-Object | Select-Object -ExpandProperty Count";
if (!fnSrc.includes(COUNT_TAIL)) {
  console.error("FAIL: 探测函数的计数量输出形状变了 —— 脚本改过，测试需同步更新");
  process.exit(2);
}
let patched = fnSrc.replace(COUNT_TAIL, "| Select-Object -ExpandProperty ProcessId");

// 改写 ②：返回匹配到的 PID 集合 + marker
const RET = "return Number(String(out).trim()) > 0;";
if (!patched.includes(RET)) {
  console.error("FAIL: 探测函数的返回语句形状变了 —— 脚本改过，测试需同步更新");
  process.exit(2);
}
patched = patched.replace(
  RET,
  "const __ids = String(out).trim().split(/\\r?\\n/).map(s=>s.trim()).filter(Boolean); " +
    "return { running: __ids.length > 0, ids: __ids, count: __ids.length, marker: typeof marker !== 'undefined' ? marker : null };"
);

const hasPpidExclusion = /ParentProcessId -ne/.test(fnSrc);
const hasMarkerExclusion = /CommandLine -notlike/.test(fnSrc);

const tmpDir = path.join(os.tmpdir(), "mcode-probe-test");
fs.mkdirSync(tmpDir, { recursive: true });
const tmpMod = path.join(tmpDir, "extracted-probe.mjs");
fs.writeFileSync(
  tmpMod,
  [
    "import crypto from 'node:crypto';",
    "import fs from 'node:fs';",
    "import path from 'node:path';",
    "import os from 'node:os';",
    "import { execFileSync } from 'node:child_process';",
    "const log = (...a) => {};",
    patched,
    "export default isMCodeRunning;",
  ].join("\n")
);
const probe = (await import(pathToFileURL(tmpMod).href + `?t=${Date.now()}`)).default;

function psRaw(script) {
  return String(
    execFileSync("powershell", ["-NoProfile", "-NonInteractive", "-Command", script], {
      encoding: "utf8",
      timeout: 60000,
      windowsHide: true,
    })
  ).trim();
}

const results = [];
const record = (name, pass, detail) => {
  results.push({ name, pass, detail });
  console.log(`${pass ? "PASS" : "FAIL"}  ${name}\n        ${detail}`);
};

// ---------- P1：探测自己派生的 powershell 不能被算进去 ----------
{
  const r = probe();
  const markerProcs = psRaw(
    `Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | ` +
      `Where-Object { $_.CommandLine -like '*${r.marker}*' } | ` +
      `Select-Object -ExpandProperty ProcessId`
  )
    .split(/\r?\n/)
    .map((s) => s.trim())
    .filter(Boolean);
  const matchedMarkerProcs = markerProcs.filter((pid) => r.ids.includes(pid));
  const pass = markerProcs.length === 1 && matchedMarkerProcs.length === 0;
  record(
    "P1 不自匹配：带 marker 的探测子进程（应恰为 1 个）必须不在匹配集合里",
    pass,
    `带marker进程=${markerProcs.length} 个(PID ${markerProcs.join(",")})；其中被算进匹配的=${matchedMarkerProcs.length} 个；匹配总数=${r.count}`
  );
}

// ---------- P2：真实匹配的子进程必须被算进去 ----------
let synthetic = null;
try {
  synthetic = spawn(
    "powershell",
    ["-NoProfile", "-NonInteractive", "-Command", "Start-Sleep -Seconds 25 # @minimax-ai\\code"],
    { windowsHide: true, stdio: "ignore" }
  );
  await new Promise((r) => setTimeout(r, 1500)); // 等它真的起来
  const r = probe();
  const syntheticPid = String(synthetic.pid);
  const detected = r.ids.includes(syntheticPid);
  record(
    "P2 不漏报：命令行含 @minimax-ai\\code 的直接子进程必须被计入匹配集合",
    detected,
    `合成进程 PID=${syntheticPid}（父=${process.pid}，即本 harness 本身）；是否在匹配集合=${detected ? "是" : "否"}；匹配总数=${r.count}`
  );
} finally {
  if (synthetic) {
    try {
      synthetic.kill();
    } catch {}
  }
}

console.log("");
console.log(`实现自检：排除规则 PPID=${hasPpidExclusion ? "有" : "无"} / marker=${hasMarkerExclusion ? "有" : "无"}`);
const allPass = results.every((x) => x.pass);
console.log(allPass ? "RESULT: PASS" : "RESULT: FAIL");
process.exit(allPass ? 0 : 1);
