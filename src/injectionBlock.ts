/**
 * 网页内容注入防护（响应侧）：在 tools/post-execute 阶段检查 web_fetch 返回的
 * 正文，命中注入时**只在正文前面插入一段警示块**，正文一字不改。
 *
 * 与 webBlock.ts 是同构的兄弟：那边管请求侧（域名拦截名单，pre-execute），
 * 这边管响应侧（正文注入，post-execute）。两者互不替代。
 *
 * 为什么 post-execute 是完整覆盖（已核实 dsh-tools 的调度实现）：
 * 调度器内部存在绕过 post-execute 的 `final-result` 分支，但逐路径核对后，
 * 它只在两种情况产生——工具未注册/不可见，以及派发前的调用方取消。
 * 一次成功派发的 web_fetch 必然经过 post-execute（dispatch → post-result 分支）。
 * 所以「只挂 post-execute」不存在漏网。
 *
 * 处置只有一档（warn）。redact / block 刻意未实现，理由如下：
 * 正则替换会毁掉安全类技术文章（它们本来就在大谈"忽略之前的指令"，命中即抹
 * 掉等于毁掉整页）；转 isError 则让一次误报直接掐掉整个可用来源，且用户无从
 * 判断那是误报还是真攻击——两者都是替用户做决定，而定位本就是"让用户判断"。
 * 宿主也没有编程式中断当前生成的 API，所以由用户自行决定是否中断。
 */
import { detectInjection } from "./auditor/injection/detect.js";
import { renderInjectionNotice } from "./auditor/injection/notice.js";
import type { InjectionReport, InjectionSettings } from "./auditor/injection/types.js";
import type { ContentBlock } from "@deepseek-ai/dsh-llm";

/** 与 webBlock.ts 共用同一套工具名识别（web_search / web_fetch / web_browse 及 tool: 前缀）。 */
const WEB_TOOL_RE = /^tool:web_|web[-_](search|fetch|browse)|^web[-_](search|fetch|browse)/i;

/** 本期只覆盖 web_fetch：web_search 的结果结构是 ItemRetainer<WebSearchSource>，改造量另计（v0.5）。 */
const FETCH_TOOL_RE = /^tool:web_fetch|^web[-_]fetch/i;

/** 取注入设置的来源：审计服务读盘得到 settings.injection。 */
export interface InjectionSettingsSource {
  getSettings(): { enabled: boolean; injection?: InjectionSettings };
}

/** 单个文本块的检测结论（供日志与测试断言）。 */
export interface BlockScan {
  index: number;
  report: InjectionReport;
}

/** 一次 web_fetch 响应的整体检测结论。 */
export interface FetchScanResult {
  /** 是否是本次关注的工具（web_fetch）。false = 直接放行。 */
  applies: boolean;
  /** 是否因设置关闭而旁路。 */
  bypassed: boolean;
  blocks: BlockScan[];
  /** 任一块命中即为 false。 */
  clean: boolean;
  /** 参与检测的文本总字节数。 */
  scannedBytes: number;
}

/** 从工具参数里取出 web_fetch 的 URL（仅用于警示块展示来源）。 */
function sourceUrlOf(args: unknown): string | undefined {
  if (args === null || typeof args !== "object") return undefined;
  const url = (args as Record<string, unknown>)["url"];
  return typeof url === "string" && url !== "" ? url : undefined;
}

/** 取出 content 里的文本块下标。 */
function textBlockIndexes(content: readonly ContentBlock[]): number[] {
  const out: number[] = [];
  for (let i = 0; i < content.length; i++) {
    if (content[i]?.type === "text") out.push(i);
  }
  return out;
}

/**
 * 对一次 web_fetch 的结果做注入检测。纯函数（不读盘、不写盘），便于测试。
 *
 * @param toolName 工具的 wire 名。
 * @param args 工具参数（取 url 展示用）。
 * @param content 工具结果的内容块。
 * @param settings 注入设置。
 * @returns 检测结论。applies=false 或 bypassed=true 时调用方应原样放行。
 */
export function scanFetchContent(
  toolName: string | undefined,
  args: unknown,
  content: readonly ContentBlock[],
  settings: InjectionSettings,
): FetchScanResult {
  const empty: FetchScanResult = { applies: false, bypassed: false, blocks: [], clean: true, scannedBytes: 0 };
  if (typeof toolName !== "string" || !WEB_TOOL_RE.test(toolName)) return empty;
  if (!FETCH_TOOL_RE.test(toolName)) return empty; // 本期只管 fetch
  if (settings.enabled !== true) {
    return { ...empty, applies: true, bypassed: true };
  }
  const blocks: BlockScan[] = [];
  let scannedBytes = 0;
  for (const index of textBlockIndexes(content)) {
    const block = content[index];
    if (block?.type !== "text") continue;
    const report = detectInjection(block.text, settings);
    scannedBytes += report.scannedBytes;
    blocks.push({ index, report });
  }
  return {
    applies: true,
    bypassed: false,
    blocks,
    clean: blocks.every((b) => b.report.clean),
    scannedBytes,
  };
}

/**
 * 在正文**前面**插入警示块，返回新的 content 数组。
 * 原有块按原顺序、原内容完整保留——这是本期的硬约束。
 *
 * @param content 原内容块。
 * @param result scanFetchContent 的结论。
 * @param args 工具参数（取来源 URL）。
 * @returns 新数组；clean 时返回原数组引用（调用方可据此判断无需替换）。
 */
export function applyInjectionNotice(
  content: readonly ContentBlock[],
  result: FetchScanResult,
  args: unknown,
): { content: ContentBlock[]; changed: boolean } {
  if (!result.applies || result.bypassed || result.clean) {
    return { content: content as ContentBlock[], changed: false };
  }
  const url = sourceUrlOf(args);
  // 合并各块的发现：警示块描述整个响应，不逐块重复
  const findings = result.blocks.flatMap((b) => b.report.findings);
  const truncated = result.blocks.some((b) => b.report.truncated);
  const notice = renderInjectionNotice(
    { clean: false, findings, normalized: true, scannedBytes: result.scannedBytes, truncated },
    url,
  );
  if (notice === "") return { content: content as ContentBlock[], changed: false };
  return {
    content: [{ type: "text", text: notice }, ...content],
    changed: true,
  };
}

/** 插件侧的判定入口：读设置 + 走上面两步，返回是否需要替换 content。 */
export function guardFetchContent(
  source: InjectionSettingsSource,
  toolName: string | undefined,
  args: unknown,
  content: readonly ContentBlock[],
): { content: ContentBlock[]; changed: boolean; result: FetchScanResult } {
  const s = source.getSettings();
  const result = scanFetchContent(toolName, args, content, s.injection ?? ({} as InjectionSettings));
  const applied = applyInjectionNotice(content, result, args);
  return { ...applied, result };
}
