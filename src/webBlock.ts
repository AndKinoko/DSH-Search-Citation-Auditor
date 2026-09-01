/**
 * 真实拦截（web 访问阻断）：在 tools/pre-execute 阶段检查 web 工具（web_search /
 * web_fetch 等）参数里的 URL 或裸域名，命中拦截名单（精确域名或 TLD）即返回
 * deny 决策——模型无法再访问被拦域名。
 *
 * 只拦 web 工具：不扫描任意工具参数，避免误伤插件自己的 citation_audit（它审计
 * 的文本本来就可能含被拦域名）。pwsh/curl 等 shell 通道不在拦截范围（属沙箱层）。
 *
 * 域名提取：完整 URL 走 scanner（PSL 归一化到 eTLD+1）；查询里不带 scheme 的裸
 * 域名单独匹配（搜索被拦域名也算一种访问）。名单读取走 mtime 热重载——手动改
 * blocklist.json 或界面点"加入拦截名单"后立即生效，无需重启。
 */
import { scan } from "./auditor/scanner.js";
import { get as pslGet } from "psl";
import type { Auditor } from "./auditor/service.js";

/** deny 决策的最小形状（与 dsh-tools 的 PreToolDecision 一致）。 */
export interface DenyDecision {
  kind: "deny";
  reason: string;
}

/** web 访问类工具（exec.name 命中即纳入拦截检查）。 */
const WEB_TOOL_RE = /^tool:web_|web[-_](search|fetch|browse)|^web[-_](search|fetch|browse)/i;

/** 裸域名（无协议前缀）匹配：查询里直接写被拦域名的情况。 */
const BARE_DOMAIN_RE = /(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}/gi;

/**
 * 检查一次工具调用是否命中拦截名单。
 * @param auditor - 审计服务（名单真源）。
 * @param name - 工具名（wire 名）。
 * @param args - 工具参数（任意形状，序列化后提取域名）。
 * @returns 命中时返回 deny 决策，否则 undefined（放行）。
 */
export function blockedToolDecision(auditor: Auditor, name: string | undefined, args: unknown): DenyDecision | undefined {
  if (typeof name !== "string" || !WEB_TOOL_RE.test(name)) return undefined;
  let text: string;
  try {
    text = JSON.stringify(args ?? {});
  } catch {
    return undefined; // 无法序列化（循环引用等）就不拦
  }
  const candidates = new Set<string>();
  for (const d of scan(text).domains) candidates.add(d); // 完整 URL 的域名（PSL 归一化）
  for (const m of text.match(BARE_DOMAIN_RE) ?? []) {
    const d = pslGet(m.toLowerCase());
    if (d) candidates.add(d); // 裸域名归一化
  }
  for (const domain of candidates) {
    if (auditor.rules.blocks(domain)) {
      return {
        kind: "deny",
        reason: `域名 ${domain} 在 Citation Auditor 拦截名单中，已禁止访问`,
      };
    }
  }
  return undefined;
}
