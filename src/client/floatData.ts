/**
 * 悬浮窗的纯数据函数（Phase 4）。
 *
 * client 半边大部分是 React 组件，node:test 跑不了；把"从会话快照里取
 * 最近一次已定稿 AI 回复文本"这类判断抽成纯函数放在这里。tsc 会把它和
 * 组件一起编译进 lib/client/，测试直接 import 编译产物。
 */

/** 会话节点里悬浮窗关心的最小形状（dsh-client-runtime 类型的结构子集）。 */
export interface FloatNode {
  kind: string;
  interrupted?: true;
  blocks?: readonly { kind: string; text?: string }[];
}

/** 会话快照里悬浮窗关心的最小形状。 */
export interface FloatSnapshot {
  running: boolean;
  partial: unknown;
  nodes: readonly FloatNode[];
}

/**
 * 宿主 client 会话快照随版本演进，悬浮窗需要的数据分散在两层：
 *  - 新宿主：会话元数据快照只含 running/openState 等字段；对话内容在
 *    `uiConversation.binding(sessionId).target('chat')` 的 ChatSnapshot 里，
 *    其中 `legacy.nodes`（ConversationNode[]）与 `legacy.partial` 承载文本。
 *  - 旧宿主：`session.getSnapshot()` 直接给 `{ running, partial, nodes }`。
 *
 * 下面是两层都能吃的宽松形状：只读 kind/interrupted/blocks[].kind|text 叶子。
 * 不要 import 宿主 UI 内部类型，运行值窄化即可（本插件只有只读消费）。
 */

/** ChatSnapshot.legacy 的宽松投影（新宿主）。 */
export interface ChatLegacyLike {
  partial?: unknown;
  runningCalls?: readonly unknown[];
  nodes?: readonly unknown[];
}

/** 宽松会话快照投影（新旧宿主都能喂）。 */
export interface FloatLikeSnapshot {
  running?: boolean;
  partial?: unknown;
  nodes?: readonly unknown[];
  legacy?: ChatLegacyLike;
}

/**
 * 从任意节点数组提取"最后一条已定稿 assistant 文本"。
 * 宿主 ConversationNode 的 assistant 节点带 blocks（AssistantBlock，text
 * kind 含 text 字段）与 interrupted 标记，与 {@link FloatNode} 形状兼容，
 * 运行时直接喂给 lastSettledAssistantText。
 */
export function settledAssistantText(nodes: readonly unknown[] | undefined): string | null {
  if (!Array.isArray(nodes) || nodes.length === 0) return null;
  return lastSettledAssistantText(nodes as readonly FloatNode[]);
}

/**
 * 从双层快照里挑出对话节点数组（优先新宿主 legacy.nodes，其次顶层 nodes）。
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

/**
 * 最近一次"已定稿"的 AI 回复文本（拼接 text 块，忽略 reasoning/tool-call）。
 * 流式中断的前缀（interrupted）不算定稿；还没有完整回复时返回 null。
 */
export function lastSettledAssistantText(nodes: readonly FloatNode[]): string | null {
  let last: FloatNode | undefined;
  for (const node of nodes) {
    if (node.kind === "assistant" && !node.interrupted) last = node;
  }
  if (last === undefined) return null;
  const parts: string[] = [];
  for (const block of last.blocks ?? []) {
    if (block.kind === "text" && typeof block.text === "string" && block.text !== "") parts.push(block.text);
  }
  const text = parts.join("\n").trim();
  return text === "" ? null : text;
}

/** 回合是否已定稿：流式期间 running 为真、partial 非空，都不能拿去审计。 */
export function isConversationSettled(snapshot: FloatLikeSnapshot): boolean {
  return snapshot.running !== true && snapshot.partial === null;
}
