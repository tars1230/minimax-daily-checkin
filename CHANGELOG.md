# Changelog

本项目遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [1.0.0] - 2026-10-24

首个公开版本。

### 特性

- **纯 HTTP 直连签到**：不启动桌面端、不拉起 TUI，单次 200–700ms，零运行时依赖。
- **默认对凭据库只读**：不设 `MCODE_CHECKIN_PERSIST_REFRESH=1` 时绝不写 `~/.minimax/auth/`。
- **写回路径多重护栏**：与上游同一把独占锁、锁内重读、进程探测、代数校验、
  先写 `auth.json` 再写 `auth-state.json` 的提交顺序、`auth.json.pending` 旁路保底。
- **幂等**：同一天重复跑返回 `already`，不重复领取。
- **溯源探针**：`tools/find-checkin-endpoint.mjs` 可复现签到接口的逆向过程。

### 修复（发布前独立代码复核的产出）

- **进程探测自匹配**：探测命令自己派生的 `powershell.exe` 会被自己的模式匹配到，
  导致探测恒为「桌面端在运行」—— 自续期写回分支永不可达。现在用随机 marker
  精确排除自匹配。
- **探测漏报**：复核建议的「按父进程 PID 排除」会造成真实漏报（任何恰好是脚本
  node 直接子进程的匹配进程被静默丢弃），已移除该排除，改为只用 marker。
- **OAuth 超时**：token 端点无响应时按「可能已消费 refresh_token」处理，判致命
  并明确要求 `mcode login`，不再标成可重试。
- **generation 纪律**：浮点代数不再可能被写进 `auth-state.json`（上游要求 safe integer）。
- **锁内歧义复查**：持锁期间凭据库若出现多记录歧义，立即中止而非轮换错账号。
- **`realUserID` 明文落日志**：改为指纹（md5 前 8 位）。
- **硬编码安装路径**：改为多候选自动探测 + `MCODE_CODE_PACKAGE_JSON` 覆盖。
- **域名环境变量不分区域**：拆成 `MCODE_AGENT_ORIGIN_CN/_EN`、`MCODE_ACCOUNT_ORIGIN_CN/_EN`。

### 已知边界

见 README「已知边界」章节 —— cn 域沿用旧域名（实测同源可用）、pending 采纳依赖
「代数更大 ⇒ RT 还活着」的代理、OAuth 超时的致命化处理、进程探测基于命令行模式匹配。

[1.0.0]: https://github.com/tars1230/minimax-daily-checkin/releases/tag/v1.0.0
