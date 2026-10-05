/**
 * 验证**已安装产物**能处理宿主真实契约形状的节点。
 *
 * 这是「不显示最后一次输出的审计」的护栏：修复前实现只认 kind==='assistant'
 * 且读顶层 blocks，而宿主发的是 kind==='assistant-step' + data.blocks，
 * 于是恒返回 null、永不发起审计、面板空白且无任何报错。
 *
 * 直接 import profile 下的编译产物跑真实形状。
 */
import { pathToFileURL } from "node:url";

const TARGETS = [
  ["web", "C:/Users/MingHua/.dsh/profiles/web/node_modules/dsh-citation-auditor/lib/client/floatData.js"],
  ["desktop", "C:/Users/MingHua/.dsh/profiles/desktop/node_modules/dsh-citation-auditor/lib/client/floatData.js"],
];

const node = (kind, data) => ({ key: `${kind}-1`, kind, id: "n1", target: "chat", data });
const text = (t) => ({ kind: "text", text: t });
const assistantStep = (status, blocks) =>
  node("assistant-step", { status, turn: 1, step: 1, blocks, finalNode: { kind: "assistant", seq: 1, blocks } });
const toolCallNode = (name, argsRaw, content) =>
  node("tool-call", {
    root: {
      kind: "tool-result",
      seq: 1,
      time: 0,
      callId: "c1",
      call: name === null ? null : { name, argsRaw },
      callTime: 0,
      content: content ?? [],
      isError: false,
      subCalls: [],
    },
  });

let bad = 0;
const check = (ok, label) => {
  console.log(`  ${ok ? "\u2713" : "\u2717"} ${label}`);
  if (!ok) bad++;
};

for (const [name, path] of TARGETS) {
  console.log(`\n=== ${name} ===`);
  const { settledAssistantText, blocksOf, isInterruptedNode } = await import(pathToFileURL(path).href);

  // 1. 真实 assistant-step：这条不过就意味着面板永远空白
  const a = assistantStep("settled", [
    { kind: "reasoning", text: "先搜" },
    { kind: "tool-call", callId: "c1", name: "web_search", argsRaw: '{"query":"X"}' },
    text("资料见 https://source.example/x。"),
  ]);
  const outA = settledAssistantText([a]);
  check(outA !== null, "真实 assistant-step 能取出审查输入");
  check((outA ?? "").includes("source.example"), "正文来源被抽出");

  // 2. 真实三段式回合
  const round = [
    node("user", { content: [{ type: "text", text: "查 Y" }] }),
    assistantStep("settled", [{ kind: "tool-call", callId: "c1", name: "web_search", argsRaw: '{"query":"Y"}' }, text("查一下。")]),
    toolCallNode("web_search", '{"query":"Y"}', [{ type: "text", text: "命中 https://a.example/1" }]),
    assistantStep("settled", [text("结论：Y。")]),
  ];
  const outR = settledAssistantText(round);
  check(outR !== null && outR.includes("a.example"), "工具结果来源纳入审查输入");
  check((outR ?? "").includes("结论：Y"), "最终回答正文保留");

  // 3. 中断/流式不得被当成定稿
  check(settledAssistantText([assistantStep("running", [text("流式")])]) === null, "running 不审");
  check(settledAssistantText([assistantStep("interrupted", [text("半截")])]) === null, "interrupted 不审");

  // 4. 旧形态仍兼容（legacy.nodes 是记录级 ConversationNode）
  check(
    settledAssistantText([{ kind: "assistant", blocks: [text("旧宿主 https://legacy.example")] }])?.includes("legacy.example") === true,
    "旧宿主顶层 blocks 形态仍可用",
  );

  // 5. blocksOf / isInterruptedNode 导出且行为正确
  check(typeof blocksOf === "function" && blocksOf(a).length === 3, "blocksOf 读 data.blocks");
  check(isInterruptedNode(assistantStep("interrupted", [])) === true, "isInterruptedNode 认 status");
}

console.log(bad === 0 ? "\n两份安装产物均能处理宿主真实契约形状" : `\n${bad} 项未通过`);
process.exit(bad === 0 ? 0 : 1);