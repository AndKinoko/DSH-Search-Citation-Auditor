/** Citation Auditor 领域类型。 */

export type Mode = "whitelist" | "normal" | "simple";

export type Level = "trusted" | "suspicious" | "warning" | "critical";

export type JudgedBy =
  | "whitelist"
  | "blocklist"
  | "timeline_2023"
  | "score_engine"
  | "unverifiable";

export interface Verdict {
  domain: string;
  score: number; // 0–100
  level: Level;
  reasons: string[];
  judgedBy: JudgedBy;
  /** 创建日期（成功查询/缓存命中时为 ISO 字符串，否则 undefined）。 */
  creationDate?: string;
  /** 来源类型：API查询 / 缓存 / 白名单 / 未能验证（报表"来源类型"字段用）。 */
  sourceKind?: "API查询" | "缓存" | "白名单" | "拦截名单" | "未能验证";
}

export interface ListEntry {
  domain: string;
  reason: string;
  date: string; // ISO
}

export interface Settings {
  /** 插件总开关：关闭 = 完全休眠（audit 立即返回空报表、零网络、不加载名单）。 */
  enabled: boolean;
  mode: Mode;
  blocklistEnabled: { whitelist: boolean; normal: boolean; simple: boolean };
  whitelistEnabled: { normal: boolean };
  /** ageQuery.code 已迁移到独立 ageQuery.js 文件；此字段仅为兼容旧配置保留，不再使用。 */
  ageQuery: { code: string; enabled: boolean };
  /** 仅允许 treatAsNew（禁止 treatAsOld）。 */
  onFailure: "treatAsNew";
}

export const DEFAULT_SETTINGS: Settings = {
  enabled: true,
  mode: "normal",
  blocklistEnabled: { whitelist: true, normal: true, simple: true },
  whitelistEnabled: { normal: true },
  ageQuery: { code: "", enabled: false },
  onFailure: "treatAsNew",
};

export const LEVEL_ORDER: readonly Level[] = ["trusted", "suspicious", "warning", "critical"];

export const LEVEL_LABEL: Record<Level, string> = {
  trusted: "🟢 可信",
  suspicious: "🟠 可疑",
  warning: "🟡 警告",
  critical: "🔴 高危",
};

/** 只承载检测结果：任何"自动改写/拦截"都不允许。 */
export interface ScanResult {
  urls: string[];
  domains: string[];
  verdicts: Verdict[]; // 按威胁度降序
}