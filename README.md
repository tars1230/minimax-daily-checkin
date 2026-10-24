# mcode-daily-checkin

MiniMax Code 每日签到 —— **纯 HTTP 直连**，不启动桌面端、不拉起 TUI。

> 非官方工具。复刻了 MiniMax Code 桌面端的签到链路，用于自动化/无人值守场景。
> 官方客户端升级可能改变内部接口，届时本工具需要同步更新。

---

## 它解决什么问题

MiniMax Code 的 `/checkin` 只能在一个活着的 TUI 里执行。要做无人值守的每日签到，
常见的做法是驱动 TUI（PTY + 解析屏幕文本），代价是：

| 痛点 | 本工具 |
|---|---|
| 每次要拉起完整 TUI，30–60 秒 | **纯 HTTP，200–700ms** |
| 依赖 `node-pty` 原生模块 + 客户端安装路径 | **零运行时依赖**，只需 Node.js |
| 客户端升级就炸（安装目录结构会变） | 不依赖客户端可执行文件 |
| TUI 文案一改正则就瞎 | 直接调 JSON API |
| 拿不准会不会把用户踢下线 | **显式只读凭据库**，宁可少签也不动登录态 |

---

## 快速开始

```bash
node mcode-checkin-direct.mjs
```

输出（stdout）：

```json
{
  "ok": true,
  "status": "claimed",
  "streakDays": 5,
  "cycle": "✓ ✓ ✓ ✓ ✓ · ·",
  "points": 1424,
  "tokenSource": "store"
}
```

同时写入结果 JSON：

```bash
node mcode-checkin-direct.mjs --json /path/to/checkin-last.json
```

只查状态、不领取（看今天有没有得领）：

```bash
node mcode-checkin-direct.mjs --dry-run
```

### 退出码

| 码 | 含义 |
|---|---|
| `0` | `claimed`（今日已领取）/ `already`（今日已领过）/ `unavailable`（今天没得领） |
| `1` | 致命错误，需要人工介入（如执行 `mcode login`） |
| `2` | `claimable` —— 仅 `--dry-run`：今天可领但本次没领 |
| `3` | 可重试（网络抖动 / 桌面端在跑 / 令牌过期，稍后重试即可） |

---

## 前置条件

1. **Node.js ≥ 18**（用了 `node:` 前缀导入与 `fs.cp`）。
2. **MiniMax Code 至少登录过一次** —— 本工具复用桌面端已落盘的 OAuth 凭据
   （`~/.minimax/auth/<buildEnv>/<region>/mcode-public/auth.json`）。
   没有凭据就没法签到。
3. 网络能直连 `agent.minimaxi.com`（或 `agent.minimax.io`，取决于账号 region）。

---

## 安全模型（重要）

OAuth 服务端对同一 `(client_id, 用户)` **只允许一个活跃授权**，签发新的会顶掉旧的；
而 `refresh_token` 是**严格单次轮换** —— 用一次即作废。

因此：**往共享凭据库写一个「已作废」的 refresh_token，会让桌面端下次续期拿到死 token
→ 401 → 弹登录窗把你踢下线。**

本工具的应对策略是**默认对凭据库只读**，并在需要写回时逐项校验：

| 保护 | 说明 |
|---|---|
| 默认只读 | 不设 `MCODE_CHECKIN_PERSIST_REFRESH=1` 时，**绝不**写 `~/.minimax/auth/` |
| 进程探测 | 探测失败一律当作「桌面端在运行」→ 宁可不签也不轮换 |
| 写回复检 | 真正写回前再探一次进程，收窄 TOCTOU 窗口 |
| 独占锁 | 写回必须持上游同一把锁 `<authDir>/auth.lock.lock`（mkdir 独占）并在锁内重读 |
| 代数校验 | 轮换前校验 `state.status ∈ {authenticated, expired, refreshing}` 且 generation 一致 |
| 写序 | 先写 `auth.json`（保住新 token），再写 `auth-state.json`（generation 同步） |
| 绝不沿用 | 响应里没有新的 `refresh_token` → 判致命，**绝不**沿用旧值 |
| 原子写 | 主路径用「同目录临时文件 → fsync → rename」真原子替换；rename 连续失败才降级为原地覆盖写（带备份与回读校验） |
| 不吞错 | 任一步失败即致命退出，state 保持 `expired`，不回滚成 `authenticated`（那是骗桌面端说"你没事"） |

> **关于「原子写」那一行的降级兜底** —— 有意保留，说明理由：
> rename 被杀软/索引器占用而连续失败时，`auth.json` 里会留下**已被服务端作废**的旧
> `refresh_token`。此时**只有**把新 RT 写进去才能救回会话；脚本私有的
> `auth.json.pending` 桌面端根本不读，帮不上忙。原地覆盖写虽然不是原子替换
> （进程被硬杀可能留下半截 JSON），但失败模式与「直接放弃」相同（都会被踢下线），
> 成功模式则当场救回会话 —— 所以它是**弱占优**的兜底，不要因为"看起来不够原子"就关掉。

### 三条运行路径

```
access token 仍有效？
├─ 是 → 直接签到（最快，200–700ms，不需要桌面端开着）
└─ 否 → 探测桌面端是否在运行
    ├─ 在运行 → 不碰 refresh_token，等桌面端自己续期（默认最多等 10 分钟）
    └─ 未运行 → 需要 MCODE_CHECKIN_PERSIST_REFRESH=1 才自续期，否则报错退出
```

**为什么要分这么细**：共享凭据库只有一份，桌面端和本工具都是写入方。
两个写入方同时轮换 refresh_token，必有一个拿到已作废的值 —— 那一方就废了。
所以「桌面端在跑」时，本工具主动让路。

---

## 已知边界（有意保留，不是 bug）

下面几条是独立代码复核提出、**经评估后有意不修**的项。把理由写清楚，
免得后来的人以为它们是漏掉的。

| 项 | 说明 | 为什么不修 |
|---|---|---|
| **cn 域用旧域名** `agent.minimaxi.com` / `account.minimaxi.com` | 上游 prod 配置用的是 `agent.minimax.cn` / `account.minimax.cn`，旧域在上游被标为 legacy | 实测两个域名解析到**同一台服务器**（`47.116.166.79`），旧域目前仍然可用且签到接口正常。改域名属于「换一套未经端到端验证的 OAuth 流程」，风险大于收益。需要时可覆盖：`MCODE_AGENT_ORIGIN_CN` / `MCODE_ACCOUNT_ORIGIN_CN` |
| **pending 采纳依赖「代数更大 ⇒ RT 还活着」** | 若有**第三方写者**（备份恢复、手工编辑）写入代数更低的凭据，这个代理会失效，可能把已死的 RT 写回共享库 | 前提「所有写者单调递增 generation」对上游桌面端和本脚本都成立（已从上游 `app.asar` 实证）。加固要改**唯一会把凭据写进共享库**的分支，而该路径在「桌面端运行时」无法安全实测（会轮换真实 RT ⇒ 踢人下线）。触发条件也极窄：需「上次写 `auth.json` 失败」+「第三方回写更低代数」同时发生。代码里有对应注释标注 |
| **OAuth 超时按「可能已消费 RT」处理** | token 端点无响应时，服务端**可能已经**轮换了 RT，旧 RT 已死 | 5 秒超时是刻意短于上游 30 秒的 stale 阈值与重试预算。放宽到 15–30 秒会拉长持锁时间。此类错误按**致命**处理（退出码 1）并明确要求 `mcode login`，而不是标成"可重试"—— 后者会诱导用户重试并撞上 `invalid_grant` |
| **进程探测基于命令行模式匹配** | 依赖 `@minimax-ai/code` 这类字面量出现在进程命令行里 | 已用随机 marker 排除自匹配，且**不做**「父进程是 node 自身」这类粗暴排除（会漏掉真实匹配进程）。探测失败一律按「桌面端在跑」处理 → 宁可不签也不轮换 |

---

## 代码复核

本工具发布前经过一次**独立代码复核**（由未参与实现的复核者执行），结论为
「需修改后发布」。复核提出的问题与处置如下：

| 复核项 | 处置 |
|---|---|
| 进程探测自匹配（探测自己派生的 powershell 被算进去 ⇒ 探测恒为「在跑」） | **已修**：注入随机 marker 精确排除自匹配。并用定向破坏测试验证两个不变量：① 探测自身永不被计入；② 真实匹配进程永不被漏掉（后者曾因「按父进程 PID 排除」而失败，已移除该排除） |
| OAuth 超时被当成可重试，可能送掉会话 | **已修**：无响应一律按致命处理，明确提示 `mcode login` |
| generation 纪律两处破例（浮点代数可能被写进状态文件） | **已修**：统一走「取整 + 非负 + 非法值拒绝」 |
| 锁内重读未复查「多记录歧义」 | **已修**：锁内补复查，歧义即中止 |
| `realUserID` 明文落日志 | **已修**：改为指纹（md5 前 8 位） |
| 硬编码本机安装路径 | **已修**：改为多候选自动探测 + 环境变量覆盖 |
| 域名环境变量不分区域 | **已修**：拆成按 region 的独立变量 |
| 原子写降级兜底 / pending 采纳代理 / cn 域名 | **有意保留**，理由见上文「已知边界」 |

### 复现那次验证

上面那条「进程探测」修复的定向破坏测试**随仓库发布**，任何人可以复现：

```bash
node tools/test-process-detection.mjs mcode-checkin-direct.mjs
```

它从**真实脚本源码**里抽取探测函数来测（不是重写版），断言两个不变量：
① 探测自己派生的子进程永不被计入；② 一个命令行含 `@minimax-ai\code` 的**直接子进程**
必须被计入 —— 第②条正是用来挡住「按父进程 PID 排除」那类方向相反的新缺陷的。
脚本形态若变了，测试会**报错退出**而不是静默通过。

---

## 环境变量

| 变量 | 默认 | 说明 |
|---|---|---|
| `MCODE_CHECKIN_PERSIST_REFRESH` | 未设 | 设为 `1` 才允许在桌面端未运行时自续期并**写回**凭据库 |
| `MCODE_CHECKIN_WAIT_MS` | `600000` | 桌面端在跑时，等它续期的最长时间（毫秒） |
| `MCODE_CHECKIN_GRACE_MS` | `180000` | token 过期后的宽限期（服务端通常还认一会儿） |
| `MCODE_CHECKIN_FORCE_DIRECT_WRITE` | 未设 | 设为 `1` 跳过 pending 恢复路径，直接写 |
| `MCODE_CHECKIN_WRITE_ATTEMPTS` | `8` | 写凭据库的重试次数 |
| `MCODE_CHECKIN_WRITE_MAX_DELAY_MS` | `2000` | 写重试的最大退避间隔 |
| `MCODE_CHECKIN_OAUTH_TIMEOUT_MS` | `5000` | OAuth 请求超时 |
| `MCODE_CHECKIN_LOG` | `<HOME>/logs/mcode-checkin.log` | 日志路径 |
| `MCODE_AGENT_ORIGIN` | 按 region 自动 | 同时覆盖 cn/en 的签到 API origin（沙箱测试用） |
| `MCODE_AGENT_ORIGIN_CN` / `_EN` | 同上 | **按 region 单独覆盖**签到 API origin，优先于上面那个 |
| `MCODE_ACCOUNT_ORIGIN` | 按 region 自动 | 同时覆盖 cn/en 的账号 origin（沙箱测试用） |
| `MCODE_ACCOUNT_ORIGIN_CN` / `_EN` | 同上 | **按 region 单独覆盖**账号 origin |
| `MCODE_OAUTH_TOKEN_ENDPOINT` | 按 region 自动 | 覆盖 OAuth token 端点（沙箱测试用） |
| `MCODE_CODE_PACKAGE_JSON` | 自动探测 | 指定 `@minimax-ai/code/package.json` 的绝对路径（取版本号用） |
| `MINIMAX_DATA_DIR` / `MAVIS_DATA_DIR` / `MCODE_HOME` | `~/.minimax` | 数据目录覆盖 |
| `MAVIS_REGION` | 自动探测 | `cn` / `en` |

> ⚠️ **安全警告 —— `MCODE_OAUTH_TOKEN_ENDPOINT` / `MCODE_ACCOUNT_ORIGIN*` 会把 refresh_token 发到任意主机。**
>
> 这几个变量是给沙箱测试用的钩子。**一旦设置**，续期请求就会把长期有效的
> `refresh_token` 发往那个地址 —— 等于把账号的长期凭据交出去。
> 生产环境**不要**设置它们；本工具默认只连官方域名。

---

## 定时任务示例

每天凌晨 3 点跑（那时桌面端基本没开，走自续期路径，互不干扰）：

```cron
0 3 * * *  cd /path/to/repo && MCODE_CHECKIN_PERSIST_REFRESH=1 node mcode-checkin-direct.mjs --json /tmp/checkin.json
```

**建议排在你确定没在用桌面端的时段。** 白天跑会撞上桌面端自己的续期，
脚本会保守地让路（等或报错），签不到。

签到是**幂等**的 —— 同一天重复跑第二次会返回 `already`，不会重复领取。

---

## 排错

### `getaddrinfo ENOTFOUND agent.minimaxi.com`

真实的 DNS 解析失败。**注意**：PowerShell 的 `[System.Net.Dns]::GetHostAddresses()`
在解析失败时可能**静默返回空而不抛异常** —— 空结果不等于失败，务必用
`dns.lookup` 交叉验证：

```bash
node -e "require('node:dns').lookup('agent.minimaxi.com',(e,a)=>console.log(e?e.code:a))"
```

### `token` 阶段失败

```
MiniMax access token is expired and MiniMax Code is running, so this script
will not rotate its shared refresh_token ...
```

**打开一次 MiniMax Code**（它会按需续期并回写凭据库），然后重跑。
本工具不会自己去动那个共享 refresh_token —— 抢着转会把桌面端踢下线。

### `status` 阶段 401

桌面端正在续期、或凭据里的 token 已被顶掉。同样先打开一次桌面端，再重跑。

---

## 溯源

`tools/find-checkin-endpoint.mjs` 是当初用来**逆向出签到接口**的探针 ——
它扫描 MiniMax Code 安装目录里的 chunk 文件，找签到相关的 URL / 函数名。
保留它是为了让"这个接口是怎么找出来的"可复现、可审计。

```bash
node tools/find-checkin-endpoint.mjs
```

探针**不再硬编码路径**：依次尝试命令行参数 → `MCODE_CHUNKS_DIR` 环境变量 →
各平台常见安装位置。找不到就打印它试过哪些路径后退出。

```bash
node tools/find-checkin-endpoint.mjs "/path/to/MiniMax Code/resources/app.asar.unpacked"
MCODE_CHUNKS_DIR="/path/to/chunks" node tools/find-checkin-endpoint.mjs
```

---

## 目录结构

```
mcode-checkin-direct.mjs       # 主脚本（唯一必需文件）
tools/
  find-checkin-endpoint.mjs     # 逆向溯源探针（可选）
  test-process-detection.mjs    # 进程探测的定向破坏测试（可选，回归护栏）
package.json                    # 元数据（零依赖）
CHANGELOG.md                    # 变更记录
```

---

## License

MIT
