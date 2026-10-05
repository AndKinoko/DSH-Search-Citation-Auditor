/**
 * 悬浮窗的纯数据函数（Phase 4）。
 *
 * client 半边大部分是 React 组件，node:test 跑不了；把"从会话快照里取
 * 最近一次已定稿 AI 回复文本 + 本回合联网来源"这类判断抽成纯函数放在这里。
 * tsc 会把它和组件一起编译进 lib/client/，测试直接 import 编译产物。
 *
 * ============================ 形状契约（务必核对）============================
 *
 * 本文件的字段名**全部**来自宿主 .d.ts，不是猜的。此前版本按错误的假设实现
 * （读顶层 `blocks`、判 `kind === 'assistant'`），导致面板**恒不发起审计请求**
 * ——表现是「不显示最后一次输出的审计」，且全程无报错。权威来源：
 *
 *   ConversationViewNode（conversation.d.ts:109-115）
 *     { key, kind, id, target, data }          ← payload 一律在 data 里
 *
 *   ChatNode 的 kind 注册名（chat-nodes.d.ts:13由 ChatNodeDataMap 推导）
 *     'assistant-step' → AssistantChatData
 *                        { status:'running'|'settled'|'interrupted', blocks, turn, step, finalNode }
 *     'tool-call'      → ToolChatData { root: ToolCallBlock }
 *
 *   AssistantBlock（records.d.ts:26-43）
 *     {kind:'text',text} {kind:'reasoning',text} {kind:'tool-call',callId,name,argsRaw} {kind:'image'} {kind:'other'}
 *
 *   ToolCallBlock = RunningToolCall | ToolResultNode（records.d.ts:272）
 *     ToolResultNode { kind:'tool-result', call:{name,argsRaw}|null, content:ContentBlock[], subCalls, … }
 *
 * 用户消息节点 kind 为 'user'（records.d.ts:45）。
 *
 * 兼容策略：宿主形态随版本演进，旧版（与本文档注释里的错误假设一致）把 blocks
 * 直接挂在节点顶层。两边都读，以宿主契约优先。
 * ============================================================================
 */

/** AssistantBlock 的宽松投影。 */
export interface FloatBlock {
  kind: string;
  text?: string;
  /** tool-call 块：工具名与参数原文（web_fetch 的 url 在 argsRaw 里）。 */
  name?: string;
  argsRaw?: string;
}

/** ToolResultNode 的宽松投影。 */
export interface FloatToolResult {
  kind?: string;
  name?: string;
  argsRaw?: string;
  call?: { name?: string; argsRaw?: string } | null;
  content?: readonly unknown[];
  subCalls?: readonly FloatToolResult[];
}

/**
 * 会话节点的宽松投影。顶层字段是旧宿主形态；data.* 是宿主契约形态。
 * 两个都保留，读的时候按 data 优先。
 */
export interface FloatNode {
  kind: string;
  /** 旧宿主：blocks 直接挂顶层。 */
  blocks?: readonly FloatBlock[];
  /** 旧宿主：中断标记直接挂顶层。 */
  interrupted?: true;
  /** 宿主契约：节点 payload。 */
  data?: {
    status?: string;
    blocks?: readonly FloatBlock[];
    finalNode?: { blocks?: readonly FloatBlock[]; interrupted?: true };
    root?: FloatToolResult;
  };
}

/** 会话快照的宽松投影。 */
export interface FloatLikeSnapshot {
  running?: boolean;
  partial?: unknown;
  nodes?: readonly unknown[];
  legacy?: ChatLegacyLike;
}

/** ChatSnapshot.legacy 的宽松投影（新宿主）。 */
export interface ChatLegacyLike {
  partial?: unknown;
  runningCalls?: readonly unknown[];
  nodes?: readonly unknown[];
}

// ---------------------------------------------------------------------------
// 形状归一：把两种宿主形态压成同一视图
// ---------------------------------------------------------------------------

/**
 * 取节点里 assistant 的内容块。
 *
 * 优先 data.blocks（宿主契约），回退顶层 blocks（旧宿主）。
 * 两者都没有时再看 data.finalNode.blocks —— AssistantMessageNode 是定稿记录，
 * 中断标记(interrupted)就挂在那里。
 */
export function blocksOf(node: FloatNode | undefined): readonly FloatBlock[] {
  if (node === undefined) return [];
  const fromData = node.data?.blocks;
  if (Array.isArray(fromData) && fromData.length > 0) return fromData;
  if (Array.isArray(node.blocks) && node.blocks.length > 0) return node.blocks;
  const fromFinal = node.data?.finalNode?.blocks;
  if (Array.isArray(fromFinal) && fromFinal.length > 0) return fromFinal;
  return [];
}

/** 节点是否是 assistant。kind 为 'assistant-step'（契约）或 'assistant'（旧宿主）。 */
function isAssistantNode(node: FloatNode | undefined): boolean {
  if (node === undefined) return false;
  return node.kind === "assistant-step" || node.kind === "assistant";
}

/**
 * 节点是否已被中断（不算定稿）。
 *
 * 三处可能：data.status === 'interrupted'（契约）、data.finalNode.interrupted
 * （定稿记录上的标记）、顶层 interrupted（旧宿主）。
 * running 期间同样不能审——流式前缀不是结论。
 */
export function isInterruptedNode(node: FloatNode | undefined): boolean {
  if (node === undefined) return true;
  const status = node.data?.status;
  if (status === "interrupted" || status === "running") return true;
  if (node.data?.finalNode?.interrupted === true) return true;
  return node.interrupted === true;
}

// ---------------------------------------------------------------------------
// 提取
// ---------------------------------------------------------------------------

/**
 * 从任意节点数组提取「审查输入」：最后一条已定稿 assistant 文本
 * **加上**当前回合的联网工具来源。
 *
 * 为什么必须带上工具来源：模型常常只在正文里给结论、把链接全放在检索结果里。
 * 只看正文就会把「确实联网引用了 5 个来源」误判成「没有可审查的网址」。
 */
export function settledAssistantText(nodes: readonly unknown[] | undefined): string | null {
  if (!Array.isArray(nodes) || nodes.length === 0) return null;
  return auditInputText(nodes as readonly FloatNode[]);
}

/** 最后一条已定稿 assistant 的 text 块拼接结果。 */
export function lastSettledAssistantText(nodes: readonly FloatNode[]): string | null {
  let last: FloatNode | undefined;
  for (const node of nodes) {
    if (isAssistantNode(node) && !isInterruptedNode(node)) last = node;
  }
  if (last === undefined) return null;
  const parts: string[] = [];
  for (const block of blocksOf(last)) {
    if (block.kind === "text" && typeof block.text === "string" && block.text !== "") parts.push(block.text);
  }
  const text = parts.join("\n").trim();
  return text === "" ? null : text;
}

// ---------- 联网工具的来源 ----------

/**
 * 工具文本的字符预算。
 *
 * tool-result 正文常达数百 KB（整页抓取），原样拼进审查输入会让 host 侧的
 * 64KB 硬截断把**尾部**切掉——而尾部恰恰可能是真正的来源。
 * 策略：含 http 的行优先，纯文本行补位。
 */
const TOOL_TEXT_BUDGET = 48 * 1024;

/** 含协议的片段（URL 及同一行上下文）。 */
const URL_LINE_RE = /https?:\/\//i;

/** 按预算裁剪工具文本，保证含 URL 的行不被截掉。 */
export function clampToolText(text: string, budget = TOOL_TEXT_BUDGET): string {
  if (text.length <= budget) return text;
  const lines = text.split("\n");
  const kept: string[] = [];
  let used = 0;
  for (const line of lines) {
    if (!URL_LINE_RE.test(line)) continue;
    kept.push(line);
    used += line.length + 1;
  }
  for (const line of lines) {
    if (URL_LINE_RE.test(line)) continue;
    if (used + line.length + 1 > budget) continue;
    kept.push(line);
    used += line.length + 1;
  }
  return kept.join("\n");
}

/** 从 ContentBlock 递归取出文本（宿主给 {type:"text",text} 或 {kind:"text",text}）。 */
function textFromContent(block: unknown, depth = 0): string | null {
  if (depth > 4 || block === null || typeof block !== "object") return null;
  if (Array.isArray(block)) {
    const parts = block
      .map((b) => textFromContent(b, depth + 1))
      .filter((s): s is string => s !== null && s !== "");
    return parts.length === 0 ? null : parts.join("\n");
  }
  const rec = block as Record<string, unknown>;
  const t = rec["text"];
  if (typeof t === "string" && t !== "") return t;
  for (const k of ["content", "blocks", "result", "results", "data"]) {
    const inner = rec[k];
    if (Array.isArray(inner) || (inner !== null && typeof inner === "object")) {
      const got = textFromContent(inner, depth + 1);
      if (got !== null) return got;
    }
  }
  return null;
}

/** 工具是否与 web 有关（web_fetch / web_search / web_browse，及 tool: 前缀形态）。 */
function isWebTool(name: string | undefined): boolean {
  if (typeof name !== "string" || name === "") return false;
  return /web/i.test(name);
}

/** 收集单个工具节点（ToolResultNode 及其子调用）里的文本与参数。 */
function collectFromToolNode(tool: FloatToolResult | undefined, out: string[], depth = 0): void {
  if (tool === undefined || depth > 8) return;

  // 工具名与参数：web_fetch 的 url / web_search 的 query 在 argsRaw 里，
  // 比可能被摘要化的结果正文更可靠。call 为 null 时（窗口截断）回退节点自身字段。
  const name = tool.call?.name ?? tool.name;
  const argsRaw = tool.call?.argsRaw ?? tool.argsRaw;
  if (isWebTool(name) && typeof argsRaw === "string" && argsRaw !== "") {
    out.push(`${name} ${argsRaw}`);
  }

  // 结果正文：web_search 的来源链接在这些内容块里，tool-call 上根本没有 URL
  const fromContent = textFromContent(tool.content);
  if (fromContent !== null) out.push(fromContent);

  // 嵌套子调用（PTC 派生的子工具）
  for (const sub of tool.subCalls ?? []) collectFromToolNode(sub, out, depth + 1);
}

/**
 * 当前回合里联网工具涉及的来源文本。
 *
 * 回合锚点是**最后一条 user 节点**：真实时序是
 *   user → assistant-step(发起调用) → tool-call(结果) → assistant-step(最终回答)
 * 工具节点落在最终回答**之前**，按「最后一条 assistant 之后」找会全部漏掉。
 * 以 user 为锚同时排除更早回合的陈旧来源。
 *
 * 工具节点有两种形态，都认：
 *  - 节点自身 kind 为 'tool-result'（旧宿主 / 记录级节点）
 *  - kind 为 'tool-call'，payload 在 data.root（宿主契约，ToolChatData）
 */
export function currentTurnToolText(nodes: readonly FloatNode[]): string {
  let anchor = -1;
  for (let i = 0; i < nodes.length; i++) {
    if (nodes[i]?.kind === "user") anchor = i;
  }

  const parts: string[] = [];
  for (let i = anchor + 1; i < nodes.length; i++) {
    const node = nodes[i];
    if (node === undefined) continue;

    // 契约形态：kind 'tool-call'，根调用在 data.root
    const root = node.data?.root;
    if (root !== undefined) {
      collectFromToolNode(root, parts);
      continue;
    }
    // 记录形态：节点自身就是 ToolResultNode
    if (node.kind === "tool-result" || node.kind === "tool_result" || node.kind === "toolResult") {
      collectFromToolNode(node as unknown as FloatToolResult, parts);
      continue;
    }
    // assistant 块内嵌的 tool-call：参数在这里（结果另由 tool-call 节点承载）
    for (const block of blocksOf(node)) {
      if (block.kind !== "tool-call") continue;
      if (isWebTool(block.name) && typeof block.argsRaw === "string" && block.argsRaw !== "") {
        parts.push(`${block.name} ${block.argsRaw}`);
      }
    }
  }
  return parts.join("\n").trim();
}

/**
 * 审查输入 = assistant 正文 + 当前回合的联网工具来源。
 *
 * 必须以「已定稿的 assistant 回复」为前提：被打断或仍在流式的回复不是一次完整
 * 回答，此时返回内容会让面板对着一段没说完的话出报告。
 *
 * 分隔符用换行而非空格：工具结果正文很长，直接拼会让「正文最后一行的域名」与
 * 「工具结果第一行的域名」黏成一个不可解析的 token。
 */
export function auditInputText(nodes: readonly FloatNode[]): string | null {
  const assistant = lastSettledAssistantText(nodes);
  if (assistant === null) return null;
  const tools = clampToolText(currentTurnToolText(nodes));
  return tools === "" ? assistant : `${assistant}\n\n${tools}`;
}

/**
 * 从双层快照里挑出对话节点数组（优先 legacy.nodes，其次顶层 nodes）。
 * 两个面都存在但 legacy 为空数组时回退顶层（新宿主早期可能只有空 legacy）；
 * 顶层 nodes 不存在（新宿主 session 元数据面）时返回 undefined。
 */
export function pickFloatNodes(snap: FloatLikeSnapshot | undefined): readonly unknown[] | undefined {
  if (!snap) return undefined;
  const legacyNodes = snap.legacy?.nodes;
  if (Array.isArray(legacyNodes) && legacyNodes.length > 0) return legacyNodes;
  if (Array.isArray(snap.nodes) && snap.nodes.length > 0) return snap.nodes;
  return undefined;
}

/** 回合是否已定稿：流式期间 running 为真、partial 非空，都不能拿去审计。 */
export function isConversationSettled(snapshot: FloatLikeSnapshot): boolean {
  return snapshot.running !== true && snapshot.partial === null;
}