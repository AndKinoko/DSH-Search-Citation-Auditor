/**
 * scanner：正则提取 URL → 域名列表。纯函数、同步、零 IO、无状态。
 * scanner / scorer / report 均为纯函数，便于复用到 VSCode / MCP 等其他壳。
 *
 * 注册域用 PSL（Public Suffix List）解析为 eTLD+1：en.wikipedia.org → wikipedia.org、
 * example.co.uk → example.co.uk。钓鱼者只能注册 eTLD+1 级别，合法子域不该背上母域的风险分。
 */
import { get as pslGet } from "psl";

const URL_RE =
  /\bhttps?:\/\/[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+(?::\d{1,5})?(?:\/[^\s"'<>()[\]，。；：！？、】》]*)?/g;

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
      // 兜底：手动剥离协议与路径
      const afterScheme = url.replace(/^[a-z][a-z0-9+.-]*:\/\//i, "");
      const hostPort = afterScheme.split("/")[0] ?? "";
      return (hostPort.split(":")[0] ?? hostPort).toLowerCase();
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