/**
 * 悬浮窗纯数据函数测试。
 *
 * ====================== 测试数据必须来自宿主契约 ======================
 *
 * 本文件曾因「按猜测的字段名造数据」而全绿：测试喂 `{kind:"assistant",
 * blocks:[…]}`，实现也只认这个形状，于是双方一致地错。现全部 fixture 按
 * node_modules 里的权威 .d.ts 构造：
 *
 *   ConversationViewNode = { key, kind, id, target, data }
 *   assistant-step        → data: { status, blocks, turn, step, finalNode }
 *   tool-call             → data: { root: ToolCallBlock }
 *   ToolResultNode        → { kind:'tool-result', call:{name,argsRaw}, content, subCalls }
 *   AssistantBlock        → {kind:'text'|'reasoning'|'tool-call'|'image', …}
 *
 * 依据：
 *   dsh-client-ui-conversation/…/contract/conversation.d.ts:109-115
 *   dsh-client-ui-conversation/…/contract/records.d.ts:26-43, 151-176, 272
 *   dsh-client-ui-chat/…/contract/chat-nodes.d.ts:22-41
 *   dsh-client-ui-chat/…/conversation-nodes/{assistant,tool}.d.ts
 *
 * 改动本文件前请先核对上面那份契约——字段名错了就是自证假绿。
 * =====================================================================
 */
import assert from "node:assert/strict";
import test from "node:test";
import {
  isConversationSettled,
  lastSettledAssistantText,
  pickFloatNodes,
  settledAssistantText,
  clampToolText,
  blocksOf,
  isInterruptedNode,
} from "../client/floatData.js";

// ---------- 宿主契约 fixture ----------

/** ConversationViewNode 基座（宿主必须有 key/id/target，这里只给插件读到的部分）。 */
function node(kind: string, data: unknown): Record<string, unknown> {
  return { key: `${kind}-1`, kind, id: "n1", target: "chat", data };
}

/** assistant-step 节点（契约形态）。 */
function assistantStep(status: string, blocks: unknown[], opts: { interrupted?: boolean } = {}) {
  return node("assistant-step", {
    status,
    turn: 1,
    step: 1,
    blocks,
    finalNode: {
      kind: "assistant",
      seq: 1,
      time: 0,
      turn: 1,
      step: 1,
      blocks,
      ...(opts.interrupted ? { interrupted: true as const } : {}),
    },
  });
}

/** text 块。 */
const text = (t: string) => ({ kind: "text", text: t });
/** tool-call 块（assistant 内部）。 */
const toolCall = (name: string, argsRaw: string) => ({ kind: "tool-call", callId: "c1", name, argsRaw });
/** reasoning 块。 */
const reasoning = (t: string) => ({ kind: "reasoning", text: t });

/** tool-call 节点（契约形态）：payload 在 data.root。 */
function toolCallNode(opts: {
  name?: string;
  argsRaw?: string;
  content?: unknown[];
  subCalls?: unknown[];
}) {
  return node("tool-call", {
    root: {
      kind: "tool-result",
      seq: 1,
      time: 0,
      callId: "c1",
      call: opts.name === undefined ? null : { name: opts.name, argsRaw: opts.argsRaw ?? "{}" },
      callTime: 0,
      content: opts.content ?? [],
      isError: false,
      subCalls: opts.subCalls ?? [],
    },
  });
}

// ---------- 契约形态：正文提取 ----------

test("契约形态：assistant-step 的 data.blocks 被正确提取", () => {
  const nodes = [
    node("user", { content: [{ type: "text", text: "问题" }] }),
    assistantStep("settled", [reasoning("思考"), text("答案 https://a.example")]),
  ];
  assert.equal(lastSettledAssistantText(nodes as never), "答案 https://a.example");
});

test("契约形态：status=running / interrupted 不算定稿", () => {
  // 流式前缀与被打断的半截话都不是结论
  assert.equal(lastSettledAssistantText([assistantStep("running", [text("流式中")])] as never), null);
  assert.equal(lastSettledAssistantText([assistantStep("interrupted", [text("半截")])] as never), null);
  assert.equal(
    lastSettledAssistantText([assistantStep("settled", [text("半截")], { interrupted: true })] as never),
    null,
    "finalNode.interrupted 同样要挡住",
  );
});

test("契约形态：blocksOf 覆盖 data.blocks 与 data.finalNode.blocks 两处", () => {
  assert.equal(blocksOf(assistantStep("settled", [text("x")]) as never).length, 1);
  // 流式清理过内容时 data.blocks 可能为空，定稿记录 finalNode.blocks 仍有内容
  const finalOnly = node("assistant-step", { status: "settled", blocks: [], finalNode: { blocks: [text("y")] } });
  assert.equal(blocksOf(finalOnly as never).length, 1, "只有 finalNode.blocks 时也要取到");
  assert.equal(blocksOf(undefined).length, 0);
});

// ---------- 契约形态：联网来源 ----------

test("契约形态：tool-call 节点的 data.root 提供来源", () => {
  const nodes = [
    node("user", { content: [{ type: "text", text: "查一下" }] }),
    assistantStep("settled", [text("我查一下。")]),
    toolCallNode({ content: [{ type: "text", text: "来源 https://real.example/x" }] }),
    assistantStep("settled", [text("结论在这里。")]),
  ];
  const out = settledAssistantText(nodes as never);
  assert.ok(out?.includes("real.example"), "工具结果里的来源必须进入审查输入");
});

test("契约形态：web_fetch 的 URL 从 data.root.call.argsRaw 取", () => {
  const nodes = [
    node("user", { content: [{ type: "text", text: "查" }] }),
    assistantStep("settled", [text("结果如下。")]),
    toolCallNode({ name: "web_fetch", argsRaw: '{"url":"https://fetched.example/p"}' }),
  ];
  assert.ok(settledAssistantText(nodes as never)?.includes("fetched.example"));
});

test("契约形态：assistant 块内的 tool-call 参数也要纳入", () => {
  // web_search 的来源链接在结果块里，而 query 在这个块里——两者互补
  const nodes = [
    node("user", { content: [{ type: "text", text: "搜" }] }),
    assistantStep("settled", [toolCall("web_search", '{"query":"foo"}'), text("搜到了。")]),
  ];
  assert.ok(settledAssistantText(nodes as never)?.includes("web_search"));
});

test("契约形态：call 为 null（窗口截断）时不崩且仍能读 content", () => {
  const nodes = [
    node("user", { content: [{ type: "text", text: "查" }] }),
    assistantStep("settled", [text("结果。")]),
    toolCallNode({ name: undefined, content: [{ type: "text", text: "https://orphan.example/x" }] }),
  ];
  const out = settledAssistantText(nodes as never);
  assert.ok(out?.includes("orphan.example"), "call 缺失时仍应从 content 取到来源");
});

test("契约形态：嵌套 subCalls 的来源也要纳入", () => {
  const nodes = [
    node("user", { content: [{ type: "text", text: "查" }] }),
    assistantStep("settled", [text("结果。")]),
    toolCallNode({
      name: "orchestrate",
      content: [],
      subCalls: [
        {
          kind: "tool-result",
          call: { name: "web_fetch", argsRaw: '{"url":"https://nested.example/deep"}' },
          content: [],
          subCalls: [],
        },
      ],
    }),
  ];
  assert.ok(settledAssistantText(nodes as never)?.includes("nested.example"), "子调用里的来源不能漏");
});

test("契约形态：非 web 工具不混入（否则本地路径会被当成引用来源）", () => {
  const nodes = [
    node("user", { content: [{ type: "text", text: "读文件" }] }),
    assistantStep("settled", [text("读完了。")]),
    toolCallNode({ name: "read_file", argsRaw: '{"path":"https://not-source.example/x"}' }),
  ];
  const out = settledAssistantText(nodes as never);
  assert.equal(out, "读完了。", "非 web 工具的参数不得进入审查输入");
  assert.ok(!out?.includes("not-source.example"));
});

// ---------- 旧宿主形态：保持兼容 ----------

test("旧宿主形态：顶层 blocks / interrupted 仍被识别", () => {
  const nodes = [
    { kind: "user", blocks: [] },
    { kind: "assistant", blocks: [{ kind: "text", text: "旧回复 https://old.example" }] },
    { kind: "assistant", interrupted: true, blocks: [{ kind: "text", text: "被打断" }] },
  ];
  assert.equal(lastSettledAssistantText(nodes as never), "旧回复 https://old.example");
});

test("旧宿主形态：顶层 tool-result 节点仍被识别", () => {
  const nodes = [
    { kind: "user", blocks: [] },
    { kind: "assistant", blocks: [{ kind: "text", text: "查完了。" }] },
    { kind: "tool-result", name: "web_fetch", argsRaw: '{"url":"https://legacy.example/x"}', content: [{ type: "text", text: "内容" }] },
  ];
  const out = settledAssistantText(nodes as never);
  assert.ok(out?.includes("legacy.example"), "旧形态的 tool-result 仍要取到 URL");
});

test("isInterruptedNode：undefined 视为中断（不可审）", () => {
  assert.equal(isInterruptedNode(undefined), true);
});


// ---------- M-1：工具文本预算不得挤掉真正的来源 ----------

test("M-1：工具文本超预算时，含 URL 的行必须保留", () => {
  // 回归：tool-result 常达数百 KB，host 侧 64KB 硬截断会把**尾部**切掉——
  // 而尾部恰恰可能是真正的来源，等于把「修复联网无来源」的目的又抵消了。
  // 策略改为「含 http 的行优先」，纯文本行只补位。
  const filler = "无关的检索摘要行。".repeat(3000);
  const urlLine = "来源 https://critical.example/report";
  const text = clampToolText(`${filler}\n${urlLine}\n${filler}`);
  assert.ok(text.includes("critical.example"), "深处的来源行必须活下来");
  assert.ok(text.length < filler.length * 2 + urlLine.length, "结果应被收敛到预算内");
});

test("M-1：未超预算时原样返回，不做任何裁剪", () => {
  const s = "普通正文 https://a.example/x\n另一行";
  assert.equal(clampToolText(s), s, "未超预算不应改动内容");
});

test("M-1：审查输入里来源不因工具文本过长而被挤掉", () => {
  // 端到端视角：来源出现在大量填充之后，仍必须活到送审文本里（契约形态）
  const nodes = [
    node("user", { content: [{ type: "text", text: "查" }] }),
    assistantStep("settled", [text("结论在这里。")]),
    toolCallNode({ content: [{ type: "text", text: `填充内容。`.repeat(6000) + "\nhttps://tail.example/x" }] }),
  ];
  const out = settledAssistantText(nodes as never);
  assert.ok(out?.includes("tail.example"), "尾部来源必须出现在审查输入中");
});

// ---------- 契约形状回归：这就是「不显示最后一次输出的审计」的根因 ----------

test("契约回归：真实 assistant-step 节点必须能取出文本（否则永不发起审计）", () => {
  // 修复前：实现只认 kind==='assistant' 且读顶层 blocks。宿主实际发的是
  // kind==='assistant-step' + data.blocks，于是 lastSettledAssistantText 恒返回
  // null → auditInputText 恒 null → 永远不POST /audit → 面板永远空白且无报错。
  // 这条用例就是那个 bug 的护栏：形状照抄 .d.ts，不许再改回猜测值。
  const realistic = [
    { key: "u1", kind: "user", id: "u1", target: "chat", data: { content: [{ type: "text", text: "帮我查下 X" }] } },
    {
      key: "a1",
      kind: "assistant-step",
      id: "a1",
      target: "chat",
      data: {
        status: "settled",
        turn: 1,
        step: 1,
        blocks: [
          { kind: "reasoning", text: "先搜一下" },
          { kind: "tool-call", callId: "c1", name: "web_search", argsRaw: '{"query":"X"}' },
          { kind: "text", text: "X 的资料见 https://source.example/x。" },
        ],
      },
    },
  ];
  const out = settledAssistantText(realistic as never);
  assert.ok(out !== null, "真实形状下必须能取出审查输入，否则面板永远不显示审计");
  assert.ok((out ?? "").includes("source.example"), "正文里的来源必须被抽出");
});

test("契约回归：真实三段式回合（user→调用→结果→定稿）端到端可审", () => {
  // 完全照 ChatNode 契约构造的一次真实 agent 回合。
  const realistic = [
    node("user", { content: [{ type: "text", text: "查一下 Y" }] }),
    assistantStep("settled", [toolCall("web_search", '{"query":"Y"}'), text("查一下。")]),
    toolCallNode({
      name: "web_search",
      argsRaw: '{"query":"Y"}',
      content: [{ type: "text", text: "命中 https://a.example/1 与 https://b.example/2" }],
    }),
    assistantStep("settled", [text("结论：Y。来源如上。")]),
  ];
  const out = settledAssistantText(realistic as never);
  assert.ok(out !== null);
  assert.ok((out ?? "").includes("a.example"), "工具结果来源必须纳入");
  assert.ok((out ?? "").includes("b.example"));
  assert.ok((out ?? "").includes("结论：Y"), "最终回答正文必须保留");
});
