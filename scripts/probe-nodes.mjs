/**
 * 探测运行中 desktop 实例的真实会话节点结构。
 *
 * 背景：「不显示最后一次输出的审计」。端点已证明正常（verdicts 有内容），
 * 所以问题在 client 取不到送审文本。而 floatData 只认 kind==="assistant"/"user"
 * ——如果宿主实际用的是别的 kind 名（比如 "message"/"turn"/"agent"），
 * 就会一直取不到，整条链路静默失效。
 *
 * 做法：读本机磁盘上的会话日志，统计真实出现的节点 kind 与其字段。
 * 只打印**结构**（字段名与计数），不回吐正文。
 */
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { zstdDecompressSync } from "node:zlib";

const root = "C:/Users/MingHua/.dsh/sessions";

function* walk(dir, depth = 0) {
  if (depth > 3) return;
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const e of entries) {
    const p = join(dir, e.name);
    if (e.isDirectory()) yield* walk(p, depth + 1);
    else if (e.name.endsWith(".jsonl.zstd")) yield p;
  }
}

const kindCounts = new Map();
const fieldSamples = new Map();
let files = 0;

for (const file of walk(root)) {
  let text;
  try {
    const st = statSync(file);
    if (st.size < 500) continue; // 跳过空壳
    text = zstdDecompressSync(readFileSync(file)).toString("utf8");
  } catch {
    continue;
  }
  files++;
  for (const line of text.split("\n")) {
    if (!line.trim()) continue;
    let obj;
    try {
      obj = JSON.parse(line);
    } catch {
      continue;
    }
    // 会话日志的记录形态未知，先看顶层形状
    const top = Object.keys(obj);
    const sig = top.slice(0, 6).sort().join(",");
    if (!fieldSamples.has(sig)) {
      fieldSamples.set(sig, { keys: top, sample: JSON.stringify(obj).slice(0, 300) });
    }
    for (const key of ["kind", "type", "role"]) {
      const v = obj[key];
      if (typeof v === "string") {
        const k = `${key}=${v}`;
        kindCounts.set(k, (kindCounts.get(k) ?? 0) + 1);
      }
    }
  }
}

console.log(`扫到 ${files} 个非空会话文件\n`);
console.log("=== 记录形态（顶层字段组合，出现过的都列）===");
for (const [sig, info] of fieldSamples) {
  console.log(`  字段: ${sig}`);
  console.log(`  样例: ${info.sample}\n`);
}
console.log("=== kind/type/role 取值分布 ===");
for (const [k, n] of [...kindCounts].sort((a, b) => b[1] - a[1])) {
  console.log(`  ${String(n).padStart(5)}  ${k}`);
}