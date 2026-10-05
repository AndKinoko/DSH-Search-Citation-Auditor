/**
 * 抓取一次，存到 .probe-cache/，之后离线分析。
 *
 * 联网抽测会反复撞上 403/限流，且每次重抓都不可复现。缓存一次把「抓取」
 * 和「分析」解耦：分析可以随便改、随便重跑，网络只付一次代价。
 */
import { mkdirSync, writeFileSync, existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

const UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36";
const DIR = ".probe-cache";
mkdirSync(DIR, { recursive: true });

const pages = [
  ["ycombinator", "https://news.ycombinator.com/"],
  ["bbc", "https://www.bbc.com/news"],
  ["rust-blog", "https://blog.rust-lang.org/"],
  ["wiki-ai", "https://en.wikipedia.org/wiki/Artificial_intelligence"],
  ["wiki-pi", "https://en.wikipedia.org/wiki/Prompt_injection"],
  ["gnu", "https://www.gnu.org/philosophy/free-sw.html"],
  ["owasp", "https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
  ["iana", "https://www.iana.org/help/example-domains"],
  ["example", "https://example.com/"],
  ["npr", "https://text.npr.org/"],
];

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

for (const [name, url] of pages) {
  const file = join(DIR, `${name}.html`);
  if (existsSync(file)) {
    const sz = readFileSync(file).length;
    console.log(`· ${name.padEnd(12)} 已缓存 (${sz}B)`);
    continue;
  }
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), 20000);
  try {
    const res = await fetch(url, {
      signal: ctrl.signal,
      redirect: "follow",
      headers: { "user-agent": UA, accept: "text/html,text/plain,*/*" },
    });
    const body = await res.text();
    writeFileSync(file, body, "utf8");
    console.log(`· ${name.padEnd(12)} [${res.status}] ${body.length}B -> ${file}`);
  } catch (err) {
    console.log(`! ${name.padEnd(12)} 失败: ${err.message}`);
  } finally {
    clearTimeout(t);
  }
  await sleep(1500);
}
console.log("\n抓取完成。分析请跑：node scripts/probe-fp.mjs");