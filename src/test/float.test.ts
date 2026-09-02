/**
 * 悬浮窗纯数据函数测试（Phase 4）：
 * 最近定稿 AI 回复文本提取、回合定稿判断、新旧宿主双层快照适配。
 */
import assert from "node:assert/strict";
import test from "node:test";
import {
  isConversationSettled,
  lastSettledAssistantText,
  pickFloatNodes,
  settledAssistantText,
} from "../client/floatData.js";

test("lastSettledAssistantText：取最后一条未中断的 assistant 节点，拼接 text 块", () => {
  const text = lastSettledAssistantText([
    { kind: "user", blocks: [] },
    { kind: "assistant", blocks: [{ kind: "text", text: "旧回复 https://a.example" }] },
    { kind: "assistant", interrupted: true, blocks: [{ kind: "text", text: "被打断的前缀" }] },
    { kind: "assistant", blocks: [{ kind: "reasoning", text: "思考" }, { kind: "text", text: "新回复\nhttps://b.example" }] },
  ]);
  assert.equal(text, "新回复\nhttps://b.example");
});

test("lastSettledAssistantText：没有 assistant / 只有中断 / text 全空 → null", () => {
  assert.equal(lastSettledAssistantText([{ kind: "user", blocks: [] }]), null);
  assert.equal(
    lastSettledAssistantText([{ kind: "assistant", interrupted: true, blocks: [{ kind: "text", text: "x" }] }]),
    null,
  );
  assert.equal(lastSettledAssistantText([{ kind: "assistant", blocks: [{ kind: "text", text: "   " }] }]), null);
  assert.equal(lastSettledAssistantText([]), null);
});

test("isConversationSettled：running 或 partial 非空都算流式中，不可审计", () => {
  assert.equal(isConversationSettled({ running: true, partial: null, nodes: [] }), false);
  assert.equal(isConversationSettled({ running: false, partial: { text: "..." }, nodes: [] }), false);
  assert.equal(isConversationSettled({ running: true, partial: { text: "..." }, nodes: [] }), false);
  assert.equal(isConversationSettled({ running: false, partial: null, nodes: [] }), true);
});

// ---------- 新旧宿主双层快照适配（Phase 4.2） ----------

test("settledAssistantText：吃宿主 ChatSnapshot.legacy.nodes 的宽松节点", () => {
  // 新宿主 ConversationNode：assistant 带 blocks（text/reasoning/tool-call），末尾可能是 tool-result
  const legacyNodes = [
    { kind: "user", blocks: [] },
    {
      kind: "assistant",
      interrupted: true,
      blocks: [
        { kind: "reasoning", text: "思考" },
        { kind: "text", text: "被打断的半截 https://a.example" },
      ],
    },
    { kind: "tool-result", content: [] },
    {
      kind: "assistant",
      blocks: [
        { kind: "reasoning", text: "再来" },
        { kind: "text", text: "结论见 https://b.example" },
        { kind: "tool-call", name: "x", argsRaw: "{}" },
      ],
    },
    { kind: "tool-result", content: [] },
  ];
  const text = settledAssistantText(legacyNodes);
  assert.equal(text, "结论见 https://b.example", "取最后一条未中断 assistant 的 text 块，跳过 tool-result");
});

test("settledAssistantText：undefined/空数组返回 null，裸字符串不误入", () => {
  assert.equal(settledAssistantText(undefined), null);
  assert.equal(settledAssistantText([]), null);
  assert.equal(settledAssistantText([{ kind: "assistant", blocks: [{ kind: "text", text: "   " }] }]), null);
  // 宿主 AssistantBlock 的 text 字段偶发缺失/非字符串 → 忽略
  assert.equal(
    settledAssistantText([{ kind: "assistant", blocks: [{ kind: "text" }, { kind: "text", text: 42 }] }]),
    null,
  );
});

test("pickFloatNodes：优先 legacy.nodes，其次顶层 nodes，都没有返回 undefined", () => {
  assert.deepEqual(
    pickFloatNodes({ legacy: { nodes: [{ kind: "assistant" }] }, nodes: [] }),
    [{ kind: "assistant" }],
  );
  assert.deepEqual(pickFloatNodes({ nodes: [{ kind: "user" }] }), [{ kind: "user" }]);
  assert.equal(pickFloatNodes({ legacy: { nodes: [] }, nodes: [] }), undefined, "空 legacy 不回退顶层空数组外的值");
  assert.equal(pickFloatNodes({}), undefined);
  assert.equal(pickFloatNodes(undefined), undefined);
});

test("旧宿主兜底：session 快照自带 nodes 时仍能取文本", () => {
  const text = settledAssistantText([
    { kind: "assistant", blocks: [{ kind: "text", text: "旧宿主 https://c.example" }] },
  ]);
  assert.equal(text, "旧宿主 https://c.example");
  assert.equal(lastSettledAssistantText([{ kind: "assistant", blocks: [{ kind: "text", text: "x" }] }]), "x");
});
