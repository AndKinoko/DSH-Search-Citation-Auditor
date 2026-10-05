/**
 * 垃圾网址专项：内容农场 / 域名农场 / 仿冒站 这类页面对两层的压力测试。
 *
 * 与 probe-live 的分工：那边测「正常页面会不会误报」，这边测「垃圾内容
 * 会不会触发有意义的信号」，并对已知拦截域做请求侧验证。
 *
 * 只抓取与判定，不回吐页面正文——垃圾页同样可能带注入，理由同 probe-live。
 */
import { detectInjection } from "../lib/auditor/injection/detect.js";
import { extractUrls, extractDomain } from "../lib/auditor/scanner.js";
import { classify } from "../lib/auditor/scorer.js";
import { DEFAULT_SETTINGS } from "../lib/auditor/types.js";

const UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36";

/** 构造 classify 的入参，形状对齐 ScoringInput（见 src/test/core.test.ts 的 baseInput）。 */
const input = (domain, over = {}) => ({
  domain,
  mode: "normal",
  settings: {
    ...DEFAULT_SETTINGS,
    blocklistEnabled: { ...DEFAULT_SETTINGS.blocklistEnabled },
    ageQuery: { ...DEFAULT_SETTINGS.ageQuery },
  },
  blocklist: new Set(),
  blockedTlds: new Set(),
  whitelist: new Set(),
  ...over,
});

const htmlToText = (html) =>
  html
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<[^>]*>/g, " ")
    .replace(/&nbsp;/g, " ")
    .replace(/\s+/g, " ")
    .trim();

const setting = { enabled: true };

/**
 * 垃圾站候选。说明：以下域名我只**访问**，不注册、不提交任何表单、
 * 不执行页面脚本，HTTP 请求也是纯 GET。任何页面内容一律当数据处理。
 */
const junk = [
  // 域名类：短、随机、数字连字符、老旧 TLD —— 请求侧评分应当提高
  { url: "http://x5n.com/", kind: "短域名/老牌停放" },
  { url: "http://qwe123456789.xyz/", kind: "字母数字堆砌 .xyz" },
  { url: "https://free-gift-cards-2024-win.tk/", kind: "抽奖骗局典型命名" },
  { url: "https://download-crack-keygen-setup.info/", kind: "破解站命名" },

  // 内容农场：文本量大、结构重复、常见关键词
  { url: "https://www.iana.org/", kind: "对照：正常基础设施站" },
];

console.log("=== A. 请求侧：域名风险评分（不下载正文）===\n");
for (const j of junk) {
  const domain = extractDomain(j.url);
  const v = classify(input(domain));
  const badge = v.action === "deny" ? "拒绝" : v.action === "ask" ? "需确认" : "放行";
  console.log(`  ${j.url}`);
  console.log(`    ${j.kind}`);
  console.log(`    域名=${domain}  等级=${v.level}  分=${v.score}  动作=${badge}`);
  console.log(`    信号: ${v.reasons.join(" / ") || "（无）"}\n`);
}

console.log("=== B. 响应侧：抓取后跑注入检测 ===\n");
for (const j of junk) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 15000);
  let status;
  let text;
  try {
    const res = await fetch(j.url, {
      signal: ctrl.signal,
      redirect: "follow",
      headers: { "user-agent": UA },
    });
    status = res.status;
    const body = await res.text();
    text = htmlToText(body.slice(0, 1_000_000));
  } catch (err) {
    console.log(`  · ${j.url}\n     抓取失败: ${err.name}\n`);
    clearTimeout(timer);
    continue;
  }
  clearTimeout(timer);

  const r = detectInjection(text, setting);
  const rules = [...new Set(r.findings.map((f) => f.ruleId))];
  console.log(`  ${r.clean ? "\u00b7" : "!"} [${status}] ${j.url}`);
  console.log(`     ${j.kind}  正文 ${text.length} 字符`);
  console.log(`     注入判定: ${r.clean ? "干净" : "命中 " + rules.join(", ")}`);
  if (!r.clean) {
    for (const f of r.findings.slice(0, 3)) {
      console.log(`       [${f.severity}] "${f.evidence.slice(0, 70)}"`);
    }
  }
  console.log();
}

console.log("=== C. 正文里的外链是否可被抽出评分 ===\n");
const sample = `Best deals 2024! Visit https://qwe123456789.xyz/offer and https://www.gnu.org/philosophy/free-sw.html today.`;
for (const u of extractUrls(sample)) {
  const d = extractDomain(u);
  const v = classify(input(d));
  console.log(`  ${u}`);
  console.log(`    域名=${d}  等级=${v.level}  分=${v.score}  信号: ${v.reasons.join(" / ") || "（无）"}`);
}