import fs from "node:fs";
import path from "node:path";

const dir = "C:/Users/Administrator/AppData/Roaming/npm/node_modules/@minimax-ai/code/chunks";
const files = fs.readdirSync(dir).filter((f) => f.endsWith(".js"));

// For each file, search for likely checkin-related code.
const checkinUrlRe = /matrix\/api\/v1\/[a-zA-Z0-9_\-\/]*(?:checkin|reward|sign|check|integral|point|claim|daily)[a-zA-Z0-9_\-\/]*/gi;
const checkinWordRe = /(?<![A-Za-z])(dailyCheckin|claimDaily|doCheckIn|doCheckin|performCheckin|doDailyCheckin|claimDailyCheckin|reward_checkin|rewardSignIn)(?![A-Za-z])/g;
const signInPathRe = /\/sign[_-]?in|\/daily[_-]?checkin|\/reward|\/claim[_-]?reward|\/points[_-]?sign|\/integral[_-]?sign/g;

for (const f of files) {
  const p = path.join(dir, f);
  const text = fs.readFileSync(p, "utf8");
  const urlHits = [...new Set([...text.matchAll(checkinUrlRe)].map((m) => m[0]))];
  const wordHits = [...new Set([...text.matchAll(checkinWordRe)].map((m) => m[0]))];
  const signHits = [...new Set([...text.matchAll(signInPathRe)].map((m) => m[0]))];
  if (urlHits.length || wordHits.length || signHits.length) {
    console.log(`\n=== ${f} ===`);
    if (urlHits.length) console.log("  urls:", urlHits);
    if (wordHits.length) console.log("  words:", wordHits);
    if (signHits.length) console.log("  sign-paths:", signHits);
  }
}
console.log("\n[done]");
