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
  /** 来源类型：使用英文枚举，渲染时映射为中文。 */
  sourceKind?: SourceKind;
  /** 该域名命中拦截名单时的处置动作（allow=仅提醒，ask=需确认，deny=直接拦截）。 */
  action?: EnforcementAction;
}

/** 来源类型枚举：英文值，便于 i18n。 */
export type SourceKind = "api_query" | "cache" | "whitelist" | "blocklist" | "unverifiable";

/** 来源类型中文映射（报表/界面用）。 */
export const SOURCE_KIND_LABEL: Record<SourceKind, string> = {
  api_query: "API查询",
  cache: "缓存",
  whitelist: "白名单",
  blocklist: "拦截名单",
  unverifiable: "未能验证",
};

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
  /** 评分参数（可选，不设置则用默认值）。 */
  scoring?: ScoringParams;
  /** 处置策略（可选，不设置则用默认值：拦截名单命中直接拦截）。 */
  enforcement?: EnforcementPolicy;
}

/** 处置动作：allow=仅提醒（放行，只在报表标红），ask=需确认，deny=直接拦截。 */
export type EnforcementAction = "allow" | "ask" | "deny";

/** 处置策略：拦截名单命中时的动作。 */
export interface EnforcementPolicy {
  blocklist?: EnforcementAction;
}

export const DEFAULT_ENFORCEMENT: Required<EnforcementPolicy> = {
  blocklist: "deny",
};

/** 处置动作中文映射（报表/界面用）。 */
export const ENFORCEMENT_LABEL: Record<EnforcementAction, string> = {
  allow: "仅提醒",
  ask: "需确认",
  deny: "直接拦截",
};

/** 同一注册域下聚合出的 URL 结构信号（任一 URL 命中即为 true，避免同域多 URL 重复加分）。 */
export interface DomainUrlSignals {
  hasIp?: boolean;
  hasUserinfo?: boolean;
  hasShortener?: boolean;
  hasTracking?: boolean;
  deepPath?: boolean;
  longQuery?: boolean;
  nonStandardPort?: boolean;
}

/** 评分参数：允许用户自定义阈值与权重。 */
export interface ScoringParams {
  /** TLD 可信度加分（低风险 TLD 如 .edu/.gov/.org 减分，高风险如 .xyz/.top 加分）。 */
  tldTrustBonus?: number;
  /** 连字符/数字模式加分。 */
  patternBonus?: number;
  /** 域名超长加分（渐进式：每超 1 字符加 baseBonus/extraChars）。 */
  lengthBaseBonus?: number;
  lengthExtraChars?: number;
  /** 注册于 cutoffYear 年后的加分。 */
  postCutoffBonus?: number;
  cutoffYear?: number;
  /** 年龄查询失败/未启用的降级分。 */
  ageUnavailablePenalty?: number;
  /** 年龄查询不可用（未启用或无代码）的降级分。 */
  ageDisabledPenalty?: number;
  /** URL 结构信号加分（同一域名内各命中一次，不叠加）。 */
  urlIpBonus?: number;
  urlUserinfoBonus?: number;
  urlShortenerBonus?: number;
  urlTrackingBonus?: number;
  urlDeepPathBonus?: number;
  urlLongQueryBonus?: number;
  urlPortBonus?: number;
}

export const DEFAULT_SCORING: Required<ScoringParams> = {
  tldTrustBonus: 10,
  patternBonus: 15,
  lengthBaseBonus: 10,
  lengthExtraChars: 20,
  postCutoffBonus: 50,
  cutoffYear: 2023,
  ageUnavailablePenalty: 20,
  ageDisabledPenalty: 20,
  urlIpBonus: 25,
  urlUserinfoBonus: 25,
  urlShortenerBonus: 15,
  urlTrackingBonus: 5,
  urlDeepPathBonus: 5,
  urlLongQueryBonus: 3,
  urlPortBonus: 5,
};

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