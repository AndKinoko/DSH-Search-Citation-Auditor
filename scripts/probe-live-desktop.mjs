/**
 * 探测运行中 desktop 实例的审计链路。
 *
 * 问题：「不显示打开会话的最后一次输出的审计」。要区分三种成因：
 *   A  host 端点正常，但送审文本里没有网址 → 审查输入侧问题（floatData）
 *   B  送审文本有网址，但拿不到会话节点 → 会话订阅侧问题
 *   C  端点/插件本身坏了
 *
 * 本脚本只验 C 与 A 的前半段（端点能否处理含网址的文本）。
 */
const ORIGIN = "http://127.0.0.1:19387";

const post = async (path, body) => {
  const res = await fetch(`${ORIGIN}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  const text = await res.text();
  let json;
  try {
    json = JSON.parse(text);
  } catch {
    json = { raw: text.slice(0, 200) };
  }
  return { status: res.status, json };
};

const get = async (path) => {
  const res = await fetch(`${ORIGIN}${path}`);
  const text = await res.text();
  try {
    return { status: res.status, json: JSON.parse(text) };
  } catch {
    return { status: res.status, json: { raw: text.slice(0, 200) } };
  }
};

console.log("=== 1. status 端点 ===");
const st = await get("/api/citation-auditor/status");
console.log(`  HTTP ${st.status}  ok=${st.json.ok}`);
console.log(`  插件 enabled=${st.json.settings?.enabled}  mode=${st.json.settings?.mode}`);
console.log(`  名单: 白名单 ${st.json.counts?.whitelist} / 拦截 ${st.json.counts?.blocklist}`);

console.log("\n=== 2. audit 端点：裸域名（当前 scanner 不抽，应为空）===");
const bare = await post("/api/citation-auditor/audit", { text: "结论在此。详见 example.com/about 这个页面。" });
console.log(`  HTTP ${bare.status}  domains=${JSON.stringify(bare.json.domains ?? bare.json.verdicts?.map((v) => v.domain))}`);

console.log("\n=== 3. audit 端点：带协议（应抽出并评分）===");
const full = await post("/api/citation-auditor/audit", {
  text: "根据 https://en.wikipedia.org/wiki/X 与 https://www.gnu.org/philosophy/free-sw.html 的信息。",
});
console.log(`  HTTP ${full.status}`);
console.log(`  domains=${JSON.stringify(full.json.domains ?? [])}`);
console.log(`  verdicts=${JSON.stringify((full.json.verdicts ?? []).map((v) => `${v.domain}(${v.level}/${v.score})`))}`);

console.log("\n=== 4. audit 端点：长工具结果 + 尾部来源（M-1 场景）===");
const long = `${"填充内容。".repeat(5000)}\n来源 https://tail.example/report\n${"x".repeat(30000)}`;
const toolLike = await post("/api/citation-auditor/audit", { text: long });
console.log(`  HTTP ${toolLike.status}  正文 ${long.length} 字符`);
console.log(`  domains=${JSON.stringify(toolLike.json.domains ?? [])}`);

console.log("\n=== 5. 空文本（模拟送审文本为 null）===");
const empty = await post("/api/citation-auditor/audit", { text: "" });
console.log(`  HTTP ${empty.status}  ok=${empty.json.ok}  domains=${JSON.stringify(empty.json.domains ?? [])}`);