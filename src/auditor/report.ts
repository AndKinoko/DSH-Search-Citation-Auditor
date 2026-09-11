/**
 * report：纯文本报表渲染。只拼接字符串，零 IO。
 * 只呈现、不拦截、不改写原文——报表是独立追加物。
 */
import type { Verdict } from "./types.js";
import { LEVEL_LABEL, SOURCE_KIND_LABEL } from "./types.js";

const DIVIDER = "═".repeat(44);

/** 一行来源块的纯文本渲染。 */
export function renderVerdict(v: Verdict): string {
  const lines: string[] = [];
  const head = `${LEVEL_LABEL[v.level]}  ${v.score}分   ${v.domain}`;
  lines.push(head);
  for (const r of v.reasons) lines.push(`    原因: ${r}`);
  lines.push(`    来源类型: ${SOURCE_KIND_LABEL[v.sourceKind ?? "unverifiable"]}`);
  return lines.join("\n");
}

/** 完整详情报表（追加在回复末尾）。 */
export function renderReport(verdicts: Verdict[], opts: { enforcement?: string } = {}): string {
  const sections = verdicts.map(renderVerdict).join("\n\n");
  const lines = [
    DIVIDER,
    `📊 引用来源威胁度分析（${verdicts.length} 个域名，按威胁度降序）`,
    DIVIDER,
    sections,
    "─".repeat(44),
    "💡 处置建议（纯提示文字，工具不做任何拦截，报表无交互按钮）:",
    "   · 发现毒来源 → 调用 citation_manage 工具加入拦截名单 → 重新生成即可",
    "   · 误伤放行   → 调用 citation_manage 工具加入白名单并附备注",
  ];
  if (opts.enforcement) {
    lines.push(`   · 当前拦截策略：${opts.enforcement}（命中拦截名单的 web 访问按此处置）`);
  }
  lines.push(DIVIDER);
  return lines.join("\n");
}

/** 回复末尾摘要行（三档）：全部可信 / 有可疑 / 不显示。 */
export function renderSummaryLine(verdicts: Verdict[]): string | null {
  if (verdicts.length === 0) return null;
  const bad = verdicts.filter((v) => v.level !== "trusted").length;
  if (bad === 0) {
    return `🛡️ 引用审计：${verdicts.length} 个来源，全部可信`;
  }
  return `⚠️ 引用审计：${verdicts.length} 个来源，${bad} 个可疑 — 详情见下方报表`;
}