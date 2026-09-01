/**
 * 悬浮窗纯数据函数测试（Phase 4）：
 * 最近定稿 AI 回复文本提取、回合定稿判断。
 */
import assert from "node:assert/strict";
import test from "node:test";
import { isConversationSettled, lastSettledAssistantText } from "../client/floatData.js";

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
