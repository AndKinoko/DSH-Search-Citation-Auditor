/**
 * 真实拦截（web 访问处置）：在 tools/pre-execute 阶段检查 web 工具（web_search /
 * web_fetch 等）参数里的 URL 或裸域名，命中拦截名单（精确域名或 TLD）即按处置
 * 策略返回决策——deny=直接拦截，ask=需确认，allow=仅提醒（放行，只在报表标红）。
 *
 * 只拦 web 工具：不扫描任意工具参数，避免误伤插件自己的 citation_audit（它审计
 * 的文本本来就可能含被拦域名）。pwsh/curl 等 shell 通道不在拦截范围（属沙箱层）。
 *
 * 域名提取：完整 URL 走 scanner（PSL 归一化到 eTLD+1）；查询里不带 scheme 的裸
 * 域名单独匹配（搜索被拦域名也算一种访问）。名单读取走 mtime 热重载——手动改
 * blocklist.json 或界面点"加入拦截名单"后立即生效，无需重启。
 */
import { isIpLiteral } from "./auditor/scanner.js";
import { get as pslGet } from "psl";
import type { Auditor } from "./auditor/service.js";
import { DEFAULT_ENFORCEMENT } from "./auditor/types.js";

/** deny 决策的最小形状（与 dsh-tools 的 PreToolDecision 一致）。 */
export interface DenyDecision {
  kind: "deny";
  reason: string;
}

/** ask 决策：需经审批服务确认，否则拒绝（与 dsh-tools 的 PreToolDecision 一致）。 */
export interface AskDecision {
  kind: "ask";
  reason?: string;
}

/** 拦截决策：deny=直接拦截，ask=需确认。allow=放行（返回 undefined，由调用方 next()）。 */
export type BlockDecision = DenyDecision | AskDecision;

/** web 访问类工具（exec.name 命中即纳入拦截检查）。 */
const WEB_TOOL_RE = /^tool:web_|web[-_](search|fetch|browse)|^web[-_](search|fetch|browse)/i;

/** 裸域名（无协议前缀）匹配：查询里直接写被拦域名的情况。 */
const BARE_DOMAIN_RE = /(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}/gi;

/**
 * 检查一次工具调用是否命中拦截名单。
 * @param auditor - 审计服务（名单真源）。
 * @param name - 工具名（wire 名）。
 * @param args - 工具参数（任意形状，序列化后提取域名）。
 * @returns 命中时按处置策略返回 deny/ask 决策，否则 undefined（放行）。
 */
export function blockedToolDecision(auditor: Auditor, name: string | undefined, args: unknown): BlockDecision | undefined {
  if (typeof name !== "string" || !WEB_TOOL_RE.test(name)) return undefined;
  const action = auditor.getSettings().enforcement?.blocklist ?? DEFAULT_ENFORCEMENT.blocklist;
  if (action === "allow") return undefined; // 仅提醒：报表标红，不拦截

  const candidates = collectDomains(args);

  for (const domain of candidates) {
    if (auditor.rules.blocks(domain)) {
      if (action === "ask") {
        return {
          kind: "ask",
          reason: `域名 ${domain} 在 Citation Auditor 拦截名单中，需确认后访问`,
        };
      }
      return {
        kind: "deny",
        reason: `域名 ${domain} 在 Citation Auditor 拦截名单中，已禁止访问`,
      };
    }
  }
  return undefined;
}

/**
 * 从工具参数里收集候选注册域。
 *
 * 不再对整个参数做 JSON.stringify + 正则：那会漏掉**百分号编码的首字符**。
 * WHATWG 在解析主机时会先做百分号解码，所以
 *   new URL("https://%65vil.com/x").hostname === "evil.com"   ← 实际访问目标
 * 而 URL_RE 要求主机首字符是 ASCII，% 开头直接让整条分支失配；BARE_DOMAIN_RE
 * 随后从该标签的**第二个字符**开始匹配，得到 "65vil.com"。evil.com 从来没成为
 * 候选，拦截放行。
 *
 * 现在改为遍历参数树，对每个能解析成 URL 的字符串取 **url.hostname**——WHATWG
 * 已经替我们做好了百分号解码与 IDNA 映射。裸域名正则只保留给自由文本查询字段
 * （web_search 的 query），那里本来就不该有百分号编码。
 *
 * 循环安全：用 WeakSet 记录已访问对象，因此不再需要「序列化失败就整体放行」这条
 * fail-open 路径。
 */
/**
 * 参数树遍历的最大深度。
 *
 * 原实现 `depth > 12` 直接**丢弃**整个子树，于是「嵌套 13 层」即可让被拦域名
 * 完全不被收集——实测 13/20/50 层全部逃逸。而 args 是模型可控的 JSON，这种
 * 结构只需模型构造一次就能把拦截彻底关掉。纵深防御的护栏不该是攻击者可预测的常量，
 * 更不该是「丢弃」这种 fail-open 语义。
 *
 * 现在改为：深度超限只**停止下探**，但仍对已见字符串做全局兜底扫描
 * （见 collectStrings 的溢出分支），保证任何层级的域名都会进入候选。
 */
const MAX_WALK_DEPTH = 12;

function collectDomains(args: unknown): Set<string> {
  const out = new Set<string>();
  const seen = new WeakSet<object>();
  const pending: string[] = [];
  /** 超过深度上限、未能下探的字符串：单独收集，最后统一按裸域名兜底扫描。 */
  const overflow: string[] = [];

  const visit = (value: unknown, depth: number): void => {
    if (value === null || value === undefined) return;
    if (typeof value === "string") {
      pending.push(value);
      return;
    }
    if (typeof value !== "object") return;
    // 超出深度：不再下探，但把这一层对象的字符串叶子收进兜底桶
    if (depth > MAX_WALK_DEPTH) {
      collectStrings(value, overflow, 0);
      return;
    }
    if (seen.has(value)) return;
    seen.add(value);
    if (Array.isArray(value)) {
      for (const item of value) visit(item, depth + 1);
      return;
    }
    for (const item of Object.values(value as Record<string, unknown>)) visit(item, depth + 1);
  };

  try {
    visit(args, 0);
  } catch {
    // 属性 getter 抛异常等极端情况：已收集的候选仍可用，不整体放弃。
  }

  for (const raw of [...pending, ...overflow]) {
    // 完整 URL：用解析器拿 hostname（已解码 + 已 IDNA 映射）
    let host: string | null = null;
    try {
      host = new URL(raw).hostname.toLowerCase();
    } catch {
      host = null;
    }
    if (host) {
      const d = isIpLiteral(host) ? host : pslGet(host);
      if (d) out.add(d);
      continue;
    }
    // 自由文本（搜索词等）：退回归一化裸域名。查询串不该有编码主机，故不必解码。
    for (const m of raw.match(BARE_DOMAIN_RE) ?? []) {
      const d = pslGet(m.toLowerCase());
      if (d) out.add(d);
    }
  }
  return out;
}

/**
 * 深度兜底收集：把任意嵌套结构里的字符串叶子全部捞出来。
 *
 * 不设深度上限是故意的——这条路径只在「主遍历已因深度放弃」时执行，而它要解决的
 * 正是「被拦域名藏在任意深处」。参数体本身受 readJsonBody 的 64KB 上限约束
 * （routes.ts），遍历成本有界。
 */
function collectStrings(value: unknown, sink: string[], depth: number): void {
  if (value === null || value === undefined || depth > 64) return;
  if (typeof value === "string") {
    sink.push(value);
    return;
  }
  if (typeof value !== "object") return;
  if (Array.isArray(value)) {
    for (const item of value) collectStrings(item, sink, depth + 1);
    return;
  }
  try {
    for (const item of Object.values(value as Record<string, unknown>)) {
      collectStrings(item, sink, depth + 1);
    }
  } catch {
    // getter 抛异常：跳过该属性
  }
}
