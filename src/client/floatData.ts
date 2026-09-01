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
export function isConversationSettled(snapshot: FloatSnapshot): boolean {
  return !snapshot.running && snapshot.partial === null;
}
