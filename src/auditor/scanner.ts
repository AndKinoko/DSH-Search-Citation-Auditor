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

/** 从文本中提取以 http(s) 开头的 URL。 */
export function extractUrls(text: string): string[] {
  if (!text) return [];
  const matches = text.match(URL_RE) ?? [];
  const seen = new Set<string>();
  const out: string[] = [];
  for (const m of matches) {
    // 去掉末尾标点（含全角：，。；：！？、】》等）
    const cleaned = m.replace(/[.,;:!?，。；：！？、】》]+$/, "");
    if (cleaned && !seen.has(cleaned)) {
      seen.add(cleaned);
      out.push(cleaned);
    }
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
  const registrable = pslGet(host);
  if (registrable) return registrable;
  // PSL 不识别（单标签主机、内网域等）：至少两段才保留，避免把 "localhost" 当域名
  const parts = host.split(".").filter(Boolean);
  return parts.length >= 2 ? host : null;
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