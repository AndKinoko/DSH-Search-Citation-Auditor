/**
 * 对**已安装的两份产物**验证 P0–P2 修复真的到位。
 * 直接 import profile 下的编译产物——本地 lib/ 证明不了装进去的是哪一版。
 */
import { pathToFileURL } from "node:url";

const TARGETS = [
  ["web", "C:/Users/MingHua/.dsh/profiles/web/node_modules/dsh-citation-auditor/lib"],
  ["desktop", "C:/Users/MingHua/.dsh/profiles/desktop/node_modules/dsh-citation-auditor/lib"],
];

const load = (lib, rel) => import(pathToFileURL(`${lib}/${rel}`).href);

let bad = 0;
const check = (ok, label) => {
  console.log(`  ${ok ? "\u2713" : "\u2717"} ${label}`);
  if (!ok) bad++;
};

for (const [name, lib] of TARGETS) {
  console.log(`\n=== ${name} ===`);

  // --- P0-1 C-1：shouldSkipDrag 热区豁免 ---
  const { shouldSkipDrag } = await load(lib, "client/FloatWindow.js");
  class El {
    constructor(tag, attrs = {}) { this.tagName = tag.toUpperCase(); this.attrs = attrs; this.parent = null; }
    matches(sel) {
      const s = sel.trim();
      if (s.startsWith("[")) {
        const m = /^\[([^\]=]+)(?:=["']?([^\]"']+)["']?)?\]$/.exec(s);
        if (!m || m[1] === undefined) return false;
        return m[2] === undefined ? m[1] in this.attrs : String(this.attrs[m[1]]) === m[2];
      }
      return this.tagName === s.toUpperCase();
    }
    closest(sel) { let c = this; while (c) { if (sel.split(",").some((o) => c.matches(o))) return c; c = c.parent; } return null; }
    contains(o) { let c = o; while (c) { if (c === this) return true; c = c.parent; } return false; }
  }
  const savedElement = globalThis.Element;
  globalThis.Element = El;

  const ball = new El("div", { "data-citation-auditor-ball": "", role: "button" });
  const icon = new El("span", { "aria-hidden": "true" });
  icon.parent = ball;
  check(shouldSkipDrag(icon, ball) === false, "P0-1 C-1 悬浮球带 role 时仍可点");

  const panel = new El("div");
  const btn = new El("button");
  btn.parent = panel;
  check(shouldSkipDrag(btn, panel) === true, "P0-1 面板按钮仍被排除（豁免不外溢）");

  globalThis.Element = savedElement;

  // --- P0-2 C-2：AuditReportCard 不再静默 ---
  const fs = await import("node:fs");
  const cardText = fs.readFileSync(`${lib}/client/AuditReportCard.js`, "utf8");
  check(cardText.includes("writeFailed"), "P0-2 C-2 写入失败可见（writeFailed）");
  // 只看**代码**，不看注释：修订记录里引用了旧代码的 .catch(() => {}) 字面量，
  // 按整文件正则匹配会把注释误判成残留（第一版验证脚本就栽在这里）。
  const codeOnly = cardText.replace(/\/\*[\s\S]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, "");
  check(!/\.catch\(\(\) => \{\}\)/.test(codeOnly), "P0-2 C-2 代码中无空 catch 残留");

  // --- S-1 深度绕过 ---
  const { blockedToolDecision } = await load(lib, "webBlock.js");
  const { Auditor } = await load(lib, "auditor/service.js");
  const { AgeQueryFile } = await load(lib, "auditor/ageQueryFile.js");
  const { DirectoryStore } = await load(lib, "storage.js");

  const os = await import("node:os");
  const path = await import("node:path");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "verify-inst-"));
  try {
    // 构造链同 webBlock.test.ts 的 makeAuditor
    const ageFile = new AgeQueryFile(dir);
    ageFile.ensure("");
    const auditor = new Auditor(new DirectoryStore(dir), ageFile);
    auditor.init();
    auditor.rules.addToBlocklist("evil.com", "test");

    let deep = "https://evil.com/x";
    for (let i = 0; i < 30; i++) deep = { k: deep };
    check(blockedToolDecision(auditor, "web_fetch", deep) !== undefined, "S-1 深层嵌套 30 层仍被拦");

    let arr = "https://evil.com/y";
    for (let i = 0; i < 30; i++) arr = [arr];
    check(blockedToolDecision(auditor, "web_fetch", { a: arr }) !== undefined, "S-1 数组嵌套 30 层仍被拦");

    check(
      blockedToolDecision(auditor, "web_fetch", { url: "https://good.example/x" }) === undefined,
      "S-1 无害域名不误伤",
    );
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }

  // --- M-1 截断策略 ---
  const { clampToolText } = await load(lib, "client/floatData.js");
  check(typeof clampToolText === "function", "M-1 clampToolText 已导出");
  const filler = "填充行。".repeat(4000);
  const clamped = clampToolText(`${filler}\n来源 https://keep.example/x\n${filler}`);
  check(clamped.includes("keep.example"), "M-1 超预算时 URL 行被保留");
}

console.log(bad === 0 ? "\n两份安装产物均含 P0–P2 修复" : `\n${bad} 项未到位`);
process.exit(bad === 0 ? 0 : 1);