/**
 * scanner：正则提取 URL → 域名列表。纯函数、同步、零 IO、无状态。
 * scanner / scorer / report 均为纯函数，便于复用到 VSCode / MCP 等其他壳。
 *
 * 注册域用 PSL（Public Suffix List）解析为 eTLD+1：en.wikipedia.org → wikipedia.org、
 * example.co.uk → example.co.uk。钓鱼者只能注册 eTLD+1 级别，合法子域不该背上母域的风险分。
 */
import { get as pslGet } from "psl";
import type { DomainUrlSignals } from "./types.js";

// userinfo 可选段（user:pass@）：钓鱼常用 trusted.com@evil.com 混淆，不支持会导致
// 整条 URL 漏提或截断误判。IPv6 字面量（http://[::1]/）暂不支持，会漏提（fail-open）。
const URL_RE =
  /\bhttps?:\/\/(?:[^\/\s@]+@)?[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+(?::\d{1,5})?(?:\/[^\s"'<>()[\]，。；：！？、】》]*)?/g;

/** 常见短链域名（注册域级别）：隐藏真实落点，引用里出现应加分提醒。 */
const SHORTENER_DOMAINS = new Set([
  "bit.ly",
  "t.co",
  "tinyurl.com",
  "goo.gl",
  "ow.ly",
  "is.gd",
  "buff.ly",
  "t.cn",
  "dwz.cn",
  "suo.im",
  "url.cn",
]);

/** 常见追踪参数前缀：存在不代表恶意，但说明 URL 携带营销/归因标记。 */
const TRACKING_KEYS = ["utm_", "gclid", "gbraid", "wbraid", "fbclid", "msclkid", "dclid", "yclid", "mc_cid", "mc_eid", "_ga", "igshid", "ttclid"];

const IPV4_RE = /^\d{1,3}(?:\.\d{1,3}){3}$/;

/** 单条 URL 的结构信号。纯函数、同步、零 IO。 */
export interface UrlSignals {
  /** 主机是 IP 直连（无域名归属，不走 PSL 声誉）。 */
  isIp: boolean;
  /** 含 userinfo（user:pass@host）或 @ 混淆（trusted@evil），钓鱼常见手段。 */
  hasUserinfo: boolean;
  /** 短链域名：真实落点被隐藏。 */
  isShortener: boolean;
  /** 含营销/归因追踪参数。 */
  hasTracking: boolean;
  /** 路径过深（≥4 段），常用于仿冒长路径藏恶意页。 */
  deepPath: boolean;
  /** 查询串超长（≥120 字符），可能藏混淆载荷。 */
  longQuery: boolean;
  /** 非标准端口（非 80/443 或与 scheme 不匹配）。 */
  nonStandardPort: boolean;
  /** 路径段数（供阈值判断与展示）。 */
  pathDepth: number;
}

/** URL 明细：归一化后的注册域 + 结构信号。 */
export interface UrlDetail {
  url: string;
  domain: string;
  signals: UrlSignals;
}

/** 分析单条 URL 的结构信号；解析失败返回 null。 */
export function analyzeUrl(url: string): UrlSignals | null {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return null;
  }
  const host = parsed.hostname.toLowerCase();
  if (!host) return null;
  const isIp = IPV4_RE.test(host) || host.includes(":");
  // 只看 authority 段（含 @ 才算 userinfo/混淆）：路径里的 /@user 不算
  const afterScheme = url.split("://")[1] ?? "";
  const authority = afterScheme.split("/")[0] ?? "";
  const hasUserinfo = parsed.username !== "" || parsed.password !== "" || authority.includes("@");
  const registrable = pslGet(host);
  const isShortener = registrable !== null && SHORTENER_DOMAINS.has(registrable);
  const search = parsed.search.toLowerCase();
  const hasTracking = search !== "" && TRACKING_KEYS.some((k) => search.includes(k));
  const segments = parsed.pathname.split("/").filter((s) => s !== "");
  const pathDepth = segments.length;
  const deepPath = pathDepth >= 4;
  const longQuery = parsed.search.length >= 120 || url.length >= 200;
  let nonStandardPort = false;
  if (parsed.port !== "") {
    const port = Number(parsed.port);
    const isHttps = parsed.protocol === "https:";
    if (Number.isNaN(port) || (isHttps ? port !== 443 : port !== 80)) nonStandardPort = true;
  }
  return { isIp, hasUserinfo, isShortener, hasTracking, deepPath, longQuery, nonStandardPort, pathDepth };
}

/** 扫描文本，返回去重后的 URL、注册域名与逐条 URL 明细（含结构信号）。 */
export function scanDetailed(text: string): { urls: string[]; domains: string[]; details: UrlDetail[] } {
  const urls = extractUrls(text);
  const domains: string[] = [];
  const details: UrlDetail[] = [];
  for (const u of urls) {
    const d = extractDomain(u);
    if (!d) continue;
    if (!domains.includes(d)) domains.push(d);
    const signals = analyzeUrl(u);
    if (signals) details.push({ url: u, domain: d, signals });
  }
  return { urls, domains, details };
}

/** 把同一注册域的多条 URL 信号聚合成域级信号（任一命中即 true，不叠加）。 */
export function aggregateDomainSignals(details: UrlDetail[], domain: string): DomainUrlSignals {
  const out: DomainUrlSignals = {};
  for (const d of details) {
    if (d.domain !== domain) continue;
    const s = d.signals;
    if (s.isIp) out.hasIp = true;
    if (s.hasUserinfo) out.hasUserinfo = true;
    if (s.isShortener) out.hasShortener = true;
    if (s.hasTracking) out.hasTracking = true;
    if (s.deepPath) out.deepPath = true;
    if (s.longQuery) out.longQuery = true;
    if (s.nonStandardPort) out.nonStandardPort = true;
  }
  return out;
}

/**
 * IDNA 视为标签分隔符的三个码点：。／．／。
 * 它们在中文正文里也是句号，所以延伸时必须再看一眼后面是不是主机标签。
 */
function isUnicodeDot(ch: string | undefined): boolean {
  return ch === "。" || ch === "．" || ch === "｡";
}

/**
 * 把一个截断的 URL 匹配向后续延伸到 authority 的真实终点。
 *
 * 为什么必须延伸：URL_RE 的主机字符类是 ASCII-only，所以它会在 U+3002 / U+FF0E /
 * U+FF61、%2E 等字符处停下；而 WHATWG 解析器**并不**把���些当主机结束——IDNA 把前三个
 * 映射成 "."，主机解析器又在 forbidden-host 检查*之前*做百分号解码。于是
 * `https://good.com。evil.com/` 里：
 *   - 正则给出 `https://good.com`  → scanner 判 good.com
 *   - 浏览器/URL 解析给出 good.com.evil.com → 注册域其实是 evil.com
 * 判决做在了截断的前缀上，而白名单与拦截名单都查这个前缀 —— 双向绕过。模型输出
 * 完全可控该字符串，且预写白名单含 github.com / wikipedia.org。
 *
 * 延伸必须**克制**，否则会吞掉正文：U+3002 既是 IDNA 分隔符也是中文句号，
 * `https://bad.site。完。` 里它后面是正文而非主机。两条约束：
 *   1. 已经在 authority 里见过 / ? #（即路径/查询/片段已开始）→ 不再延伸；
 *   2. 分隔符之后必须是 ASCII 字母数字（像主机标签的起点）才继续。
 * 满足这两条时延伸是安全的，剩下的交给 new URL()——它对这些形态的处理本来就是对的。
 */
function extendToToken(text: string, matchStart: number, matchEnd: number): number {
  const matched = text.slice(matchStart, matchEnd);
  const schemeAt = matched.indexOf("://");
  const authority = schemeAt >= 0 ? matched.slice(schemeAt + 3) : matched;
  if (/[/?#]/.test(authority)) return matchEnd; // 路径/查询/片段已开始，后面都是正文

  let end = matchEnd;
  for (;;) {
    const ch = text[end];
    if (ch === undefined) break;
    if (ch === "%" && /^[0-9a-fA-F]{2}/.test(text.slice(end + 1, end + 3))) {
      const after = text[end + 3];
      if (after === undefined || !/[A-Za-z0-9]/.test(after)) break;
      end += 3;
    } else if (isUnicodeDot(ch)) {
      const after = text[end + 1];
      if (after === undefined || !/[A-Za-z0-9]/.test(after)) break;
      end += 1;
    } else if (/[A-Za-z0-9\-._]/.test(ch)) {
      end += 1;
    } else {
      break;
    }
  }
  return end;
}

/** 从文本中提取以 http(s) 开头的 URL。 */
export function extractUrls(text: string): string[] {
  if (!text) return [];
  const seen = new Set<string>();
  const out: string[] = [];
  URL_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = URL_RE.exec(text)) !== null) {
    // 正则可能只匹配到 URL 的前半截（Unicode 点 / %2E 之后仍属主机）。
    // 向后延伸到 token 边界，让下游的 new URL() 看到完整 authority。
    const end = extendToToken(text, m.index, m.index + m[0].length);
    const raw = text.slice(m.index, end);
    // 去掉末尾标点（含全角：，。；：！？、】》等）
    const cleaned = raw.replace(/[.,;:!?，。；：！？、】》）)]+$/, "");
    if (cleaned && !seen.has(cleaned)) {
      seen.add(cleaned);
      out.push(cleaned);
    }
    // 延伸可能吃掉后续匹配，令 lastIndex 越过它，避免死循环
    URL_RE.lastIndex = end;
  }
  return out;
}

/** 从 URL 中解析出注册域（PSL eTLD+1）。 */
export function extractDomain(url: string): string | null {
  const host = (() => {
    try {
      return new URL(url).hostname.toLowerCase();
    } catch {
      // 兜底：手动剥离协议、userinfo 与路径
      const afterScheme = url.replace(/^[a-z][a-z0-9+.-]*:\/\//i, "");
      const hostPort = afterScheme.split("/")[0] ?? "";
      const noUserinfo = hostPort.includes("@") ? (hostPort.split("@").pop() ?? hostPort) : hostPort;
      return (noUserinfo.split(":")[0] ?? noUserinfo).toLowerCase();
    }
  })();
  if (!host) return null;
  // IP 字面量必须**先于** PSL 判定：psl 会把末尾的数字标签当成一个未知的公共
  // 后缀，于是 192.168.1.1 得到 "1.1"、127.0.0.1 得到 "0.1"——一个貌似有效的
  // 错误结果。它为真还会让下面两段兜底永不执行。后果是 IP 形式的拦截条目永远
  // 命中不了（用户加进去、工具回报成功，实际拦不到任何东西），不同 IP 之间还会
  // 互相碰撞（1.2.3.4 与 9.9.3.4 都变成 "3.4"），把不同主机的缓存混在一起。
  if (isIpLiteral(host)) return host;
  const registrable = pslGet(host);
  if (registrable) return registrable;
  // PSL 不识别（单标签主机、内网域等）：至少两段才保留，避免把 "localhost" 当域名
  const parts = host.split(".").filter(Boolean);
  return parts.length >= 2 ? host : null;
}

/** IPv4 / IPv6 字面量（WHATWG 已把十进制/十六进制/八进制写法归一为常规形式）。 */
export function isIpLiteral(host: string): boolean {
  const bare = host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host;
  if (bare.includes(":")) return true; // IPv6
  return IPV4_RE.test(bare);
}

/** 扫描文本，返回去重后的 URL 与注册域名。 */
export function scan(text: string): { urls: string[]; domains: string[] } {
  const urls = extractUrls(text);
  const domains: string[] = [];
  for (const u of urls) {
    const d = extractDomain(u);
    if (d && !domains.includes(d)) domains.push(d);
  }
  return { urls, domains };
}