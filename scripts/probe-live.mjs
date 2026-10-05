/**
 * 真实网页抽测：把线上页面喂进插件的注入检测器，只回收「判定结果」。
 *
 * 安全设计（这是本脚本存在的理由）：
 *   抓到的正文**绝不进入模型上下文**。脚本只吐出 verdict + 命中的短语，
 *   而非页面全文。否则这次抽测本身就成了注入的投递通道——攻击者要对付的
 *   恰恰是读它内容的那个 agent。
 *
 * 覆盖三类：
 *   A. 正常真实页面（脏、杂、长）→ 量误报率，这是最要紧的数字
 *   B. 正经讨论提示词注入的文章 → 已知不可避免的误报，确认措辞不吓人
 *   C. 垃圾/内容农场类页面 → 看能否识别出典型特征
 *
 * 用法：node scripts/probe-live.mjs
 */
import { detectInjection } from "../lib/auditor/injection/detect.js";
import { DEFAULT_INJECTION } from "../lib/auditor/injection/types.js";
import { scanFetchContent } from "../lib/injectionBlock.js";

const UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36";

const TIMEOUT_MS = 15000;
const MAX_BYTES = 3 * 1024 * 1024; // 单页上限 3MB，防止拖垮本机

const targets = [
  // ---- A. 正常真实页面：误报率基线 ----
  { cat: "A", url: "https://example.com/", note: "最小页面" },
  { cat: "A", url: "https://news.ycombinator.com/", note: "技术论坛首页，噪音多" },
  { cat: "A", url: "https://www.gnu.org/philosophy/free-sw.html", note: "长篇散文，英文" },
  { cat: "A", url: "https://en.wikipedia.org/wiki/Artificial_intelligence", note: "维基长文，链接密" },
  { cat: "A", url: "https://stackoverflow.com/questions/18609806", note: "问答页，含代码" },
  { cat: "A", url: "https://www.bbc.com/news", note: "新闻站" },
  { cat: "A", url: "https://blog.rust-lang.org/", note: "技术博客" },

  // ---- B. 正经讨论提示词注入的文章：已知不可避免的误报 ----
  { cat: "B", url: "https://en.wikipedia.org/wiki/Prompt_injection", note: "维基条目，通篇是攻击样例" },
  { cat: "B", url: "https://owasp.org/www-project-top-10-for-large-language-model-applications/", note: "OWASP LLM Top 10" },

  // ---- C. 垃圾/内容农场类 ----
  { cat: "C", url: "https://www.iana.org/help/example-domains", note: "正常基础设施站（对照）" },
  { cat: "C", url: "https://httpbin.org/html", note: "测试页，结构简单" },
  { cat: "C", url: "https://text.npr.org/", note: "纯文本新闻" },
];

/** HTML → 文本。只抽可见文本，不执行任何脚本。 */
const htmlToText = (html) =>
  html
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<noscript[\s\S]*?<\/noscript>/gi, " ")
    .replace(/<[^>]*>/g, " ")
    .replace(/&nbsp;/g, " ")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/\s+/g, " ")
    .trim();

async function fetchText(url) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      signal: ctrl.signal,
      redirect: "follow",
      headers: { "user-agent": UA, accept: "text/html,text/plain,*/*" },
    });
    const ctype = res.headers.get("content-type") ?? "";
    // 只读前 MAX_BYTES，防止超大页面
    const buf = await res.arrayBuffer();
    const bytes = buf.byteLength;
    const slice = bytes > MAX_BYTES ? buf.slice(0, MAX_BYTES) : buf;
    const raw = new TextDecoder("utf-8", { fatal: false }).decode(slice);
    return { ok: res.ok, status: res.status, ctype, bytes, raw, finalUrl: res.url };
  } finally {
    clearTimeout(timer);
  }
}

const setting = { ...DEFAULT_INJECTION, enabled: true };
const results = [];

for (const t of targets) {
  let got;
  try {
    got = await fetchText(t.url);
  } catch (err) {
    results.push({ ...t, status: `ERR ${err.name}` });
    console.log(`\u00b7  ${t.cat}  ${t.url}\n     抓取失败: ${err.name}`);
    continue;
  }

  const text = got.ctype.includes("html") ? htmlToText(got.raw) : got.raw;
  const t0 = performance.now();
  const r = detectInjection(text, setting);
  const ms = performance.now() - t0;

  // 走一遍生产封装，确认 scanFetchContent 结论一致
  const blocks = [{ type: "text", text }];
  const scan = scanFetchContent("tool:web_fetch", { url: t.url }, blocks, setting);

  const rules = [...new Set(r.findings.map((f) => f.ruleId))];
  results.push({
    ...t,
    status: got.status,
    bytes: got.bytes,
    chars: text.length,
    clean: r.clean,
    rules,
    ms,
    truncated: r.truncated,
    scanClean: scan.clean,
    evidence: r.findings
      .slice(0, 3)
      .map((f) => ({ rule: f.ruleId, sev: f.severity, snippet: f.evidence.slice(0, 70) })),
  });

  console.log(
    `${r.clean ? "\u00b7" : "!"}  ${t.cat}  [${got.status}] ${t.url}\n` +
      `     ${t.note}\n` +
      `     ${got.ctype.split(";")[0] || "?"}  ${got.bytes}B  正文 ${text.length} 字符  扫描 ${ms.toFixed(0)}ms` +
      `${r.truncated ? " (已截断)" : ""}\n` +
      `     判定: ${r.clean ? "干净" : "命中 " + rules.join(", ")}`,
  );
}

// ---------------------------------------------------------------------------
// 汇总
// ---------------------------------------------------------------------------

const ok = results.filter((r) => typeof r.clean === "boolean");
const group = (cat) => ok.filter((r) => r.cat === cat);
const line = (cat, label) => {
  const g = group(cat);
  const hits = g.filter((r) => !r.clean);
  console.log(
    `${label}  抓取成功 ${g.length}  命中 ${hits.length}  误报率 ${g.length ? ((hits.length / g.length) * 100).toFixed(0) : "-"}%`,
  );
  return hits;
};

console.log("\n================ 汇总 ================");
const hitsA = line("A", "A 正常页面（误报率，越低越好）");
const hitsB = line("B", "B 注入科普文章（已知误报，可接受）");
const hitsC = line("C", "C 其它真实页面");

console.log(`\n总耗时：最慢 ${Math.max(...ok.map((r) => r.ms ?? 0)).toFixed(0)}ms`);

// 只输出命中项的证据短语，长度截断——不回吐页面正文
for (const r of [...hitsA, ...hitsB, ...hitsC]) {
  console.log(`\n--- ${r.url}  (${r.note})`);
  for (const e of r.evidence) {
    console.log(`    [${e.rule}/${e.sev}] "${e.snippet}"`);
  }
}

process.exit(0);