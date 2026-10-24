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
| 原子写 | 写前备份原字节；写坏时尽力回滚，绝不留下半截 JSON |
| 不吞错 | 任一步失败即致命退出，state 保持 `expired`，不回滚成 `authenticated`（那是骗桌面端说"你没事"） |

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
| `MCODE_AGENT_ORIGIN` | 按 region 自动 | 覆盖签到 API origin（沙箱测试用） |
| `MCODE_OAUTH_TOKEN_ENDPOINT` | 按 region 自动 | 覆盖 OAuth token 端点（沙箱测试用） |
| `MINIMAX_DATA_DIR` / `MAVIS_DATA_DIR` / `MCODE_HOME` | `~/.minimax` | 数据目录覆盖 |
| `MAVIS_REGION` | 自动探测 | `cn` / `en` |

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

（路径目前硬编码在脚本顶部 `dir` 变量里，按自己的安装位置改。）

---

## 目录结构

```
mcode-checkin-direct.mjs       # 主脚本（唯一必需文件）
tools/
  find-checkin-endpoint.mjs     # 逆向溯源探针（可选）
```

---

## License

MIT
