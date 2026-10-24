#!/usr/bin/env node
/**
 * 溯源探针 —— 逆向出 MiniMax Code 的签到接口是怎么找出来的。
 *
 * 扫描 MiniMax Code 安装目录里的 chunk 文件，找出所有与「签到 / 积分 / 奖励」
 * 相关的 URL 与函数名。这是 mcode-daily-checkin 的接口发现过程的可复现版本。
 *
 * 用法：
 *   node tools/find-checkin-endpoint.mjs [mcode 安装目录]
 *
 * 默认会依次尝试这些位置（找到第一个存在的就停）：
 *   1. 命令行参数
 *   2. 环境变量 MCODE_CHUNKS_DIR
 *   3. %APPDATA%\npm\node_modules\@minimax-ai\code\chunks   （npm 全局安装的 CLI）
 *   4. <MiniMax Code 安装目录>\resources\app\chunks
 */
import fs from "node:fs";
import path from "node:path";
import os from "node:os";

function resolveChunksDir() {
  const arg = process.argv[2];
  if (arg) return path.resolve(arg);

  const fromEnv = process.env.MCODE_CHUNKS_DIR;
  if (fromEnv && fs.existsSync(fromEnv)) return path.resolve(fromEnv);

  const candidates = [
    // npm 全局安装的 CLI
    path.join(
      process.env.APPDATA || path.join(os.homedir(), "AppData", "Roaming"),
      "npm", "node_modules", "@minimax-ai", "code", "chunks",
    ),
    // Windows 桌面端安装目录（10/16 升级后布局变了，两种都试）
    "D:/Program Files/MiniMax/resources/app/chunks",
    "D:/Program Files/MiniMax/MiniMax Code/resources/app/chunks",
    // macOS
    "/Applications/MiniMax Code.app/Contents/Resources/app/chunks",
  ];
  for (const c of candidates) {
    if (fs.existsSync(c)) return path.resolve(c);
  }
  return null;
}

const dir = resolveChunksDir();
if (!dir) {
  console.error(
    "[x] 找不到 mcode chunks 目录。\n" +
    "    用法: node tools/find-checkin-endpoint.mjs <chunks 目录>\n" +
    "    或设置环境变量 MCODE_CHUNKS_DIR",
  );
  process.exit(1);
}

console.log(`[i] 扫描目录: ${dir}\n`);

const files = fs.readdirSync(dir).filter((f) => f.endsWith(".js"));

// 每类模式各来一份：URL 形态、标识符形态、接口路径形态
const checkinUrlRe =
  /matrix\/api\/v1\/[a-zA-Z0-9_\-\/]*(?:checkin|reward|sign|check|integral|point|claim|daily)[a-zA-Z0-9_\-\/]*/gi;
const checkinWordRe =
  /(?<![A-Za-z])(dailyCheckin|claimDaily|doCheckIn|doCheckin|performCheckin|doDailyCheckin|claimDailyCheckin|reward_checkin|rewardSignIn)(?![A-Za-z])/g;
const signInPathRe =
  /\/sign[_-]?in|\/daily[_-]?checkin|\/reward|\/claim[_-]?reward|\/points[_-]?sign|\/integral[_-]?sign/g;

for (const f of files) {
  const p = path.join(dir, f);
  const text = fs.readFileSync(p, "utf8");
  const urlHits = [...new Set([...text.matchAll(checkinUrlRe)].map((m) => m[0]))];
  const wordHits = [...new Set([...text.matchAll(checkinWordRe)].map((m) => m[0]))];
  const signHits = [...new Set([...text.matchAll(signInPathRe)].map((m) => m[0]))];
  if (urlHits.length || wordHits.length || signHits.length) {
    console.log(`=== ${f} ===`);
    if (urlHits.length) console.log("  urls:", urlHits);
    if (wordHits.length) console.log("  words:", wordHits);
    if (signHits.length) console.log("  sign-paths:", signHits);
  }
}
console.log("\n[done]");
