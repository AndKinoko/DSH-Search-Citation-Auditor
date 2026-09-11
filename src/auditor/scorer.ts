/**
 * scorer：三模式评分引擎。纯函数——所有输入显式传入，无 IO、无内部状态。
 *
 * 优先级：拦截名单 > 模式主逻辑（受每模式 blocklistEnabled 开关控制）。
 * 查不到年龄：ageQuery 启用时按 treatAsNew（+50，标红）；
 * 未启用时只记可疑（+20）——没开查询就默认全世界可疑，报表全是噪音。
 * 禁止 treatAsOld。
 *
 * 增强评分特性：
 * - TLD 可信度分级：.edu/.gov/.org 低风险，.xyz/.top/.shop 高风险
 * - 渐进式域名长度评分：超过阈值后每多 N 字符加固定分
 * - IDN/punycode 检测：国际化域名是钓鱼常见手段
 * - URL 结构信号：IP 直连、userinfo/@ 混淆、短链、追踪参数、深路径、超长查询、非标准端口
 * - 可配置阈值：通过 Settings.scoring 自定义权重
 */
import { parse as pslParse } from "psl";
import type { Level, Mode, Settings, Verdict, ScoringParams, SourceKind, DomainUrlSignals } from "./types.js";
import { DEFAULT_SCORING } from "./types.js";

export interface ScoringInput {
  domain: string;
  mode: Mode;
  settings: Settings;
  /** 拦截名单条目（去重后的域名）。 */
  blocklist: Set<string>;
  /** 拦截名单中的 TLD（以 "." 开头，如 ".xyz"）。 */
  blockedTlds: Set<string>;
  /** 白名单条目（去重后的域名）。 */
  whitelist: Set<string>;
  /** 解析出的创建日期（ISO 字符串）。undefined = 未能验证。 */
  creationDate?: string;
  /** 未能验证年龄的原因："disabled"=ageQuery 未启用；"failed"=已启用但查询失败。与 creationDate 互斥使用。 */
  ageUnavailable?: "disabled" | "failed";
  /** 同一注册域聚合出的 URL 结构信号（任一 URL 命中即 true）。 */
  urlSignals?: DomainUrlSignals;
}

const LEVEL_CRITICAL = 70;
const LEVEL_WARNING = 40;
const LEVEL_SUSPICIOUS = 20;

/** 高风险 TLD 列表：这些 TLD 常被用于垃圾/钓鱼域名。 */
const HIGH_RISK_TLDS = new Set(["xyz", "top", "shop", "site", "online", "club", "work", "buzz", "icu", "tk", "ml", "ga", "cf", "gq"]);

/** 低风险 TLD 列表：这些 TLD 通常用于合法/权威站点。 */
const LOW_RISK_TLDS = new Set(["edu", "gov", "mil", "org"]);

/** 检测 IDN/punycode 域名（国际化域名，常用于钓鱼）。 */
function isIdnDomain(domain: string): boolean {
  // punycode 编码以 xn-- 开头
  return domain.includes("xn--");
}

/** 获取 TLD 的可信度等级：-1=低风险（减分），0=中性，1=高风险（加分）。 */
function getTldRiskLevel(domain: string): -1 | 0 | 1 {
  const parsed = pslParse(domain);
  const tld = parsed.tld ?? "";
  if (LOW_RISK_TLDS.has(tld)) return -1;
  if (HIGH_RISK_TLDS.has(tld)) return 1;
  return 0;
}

export function levelFromScore(score: number): Level {
  if (score >= LEVEL_CRITICAL) return "critical";
  if (score >= LEVEL_WARNING) return "warning";
  if (score >= LEVEL_SUSPICIOUS) return "suspicious";
  return "trusted";
}

function isBlocklistHit(input: ScoringInput): boolean {
  return input.blocklist.has(input.domain);
}

function tldBlocked(input: ScoringInput): boolean {
  // 用 PSL 取真实公共后缀：".xyz" 只命中 xyz；".uk" 也命中其下的 co.uk（TLD 级拦截的宽松语义）
  const tld = pslParse(input.domain).tld;
  if (!tld) return false;
  for (const entry of input.blockedTlds) {
    const suffix = entry.replace(/^\./, "").toLowerCase();
    if (suffix !== "" && (tld === suffix || tld.endsWith(`.${suffix}`))) return true;
  }
  return false;
}

/** 普通模式多信号评分。 */
export function scoreNormal(input: ScoringInput): Verdict {
  const reasons: string[] = [];
  const domain = input.domain;
  let score = 0;
  const source: SourceKind = input.creationDate ? "api_query" : "unverifiable";
  const params: Required<ScoringParams> = { ...DEFAULT_SCORING, ...(input.settings.scoring ?? {}) };

  // TLD 拦截与精确域名一样受当前模式 blocklistEnabled 开关控制：
  // 开关关闭 = 该模式不用任何拦截名单条目（含 .xyz/.shop 这类 TLD 后缀）。
  if (input.settings.blocklistEnabled[input.mode] && tldBlocked(input)) {
    score += 40;
    reasons.push("TLD 在拦截名单");
  }

  // TLD 可信度分级：低风险 TLD 减分，高风险 TLD 加分
  const tldRisk = getTldRiskLevel(domain);
  if (tldRisk === -1) {
    score -= params.tldTrustBonus;
    reasons.push("TLD 为低风险类型（.edu/.gov/.org）");
  } else if (tldRisk === 1) {
    score += params.tldTrustBonus;
    reasons.push("TLD 为高风险类型");
  }

  // IDN/punycode 检测：国际化域名是钓鱼常见手段
  if (isIdnDomain(domain)) {
    score += 15;
    reasons.push("域名使用 punycode 编码（可能是国际化域名钓鱼）");
  }

  // 连字符/数字模式检测
  const hyphens = (domain.match(/-/g) ?? []).length;
  const digits = (domain.match(/\d/g) ?? []).length;
  if (hyphens >= 2 || digits >= 3) {
    score += params.patternBonus;
    reasons.push(`域名含 ${hyphens} 个连字符 / ${digits} 个数字`);
  }

  // 渐进式域名长度评分：超过阈值后每多 N 字符加固定分
  if (domain.length > 30) {
    const extraChars = domain.length - 30;
    const lengthBonus = Math.min(params.lengthBaseBonus, Math.floor(extraChars / params.lengthExtraChars) + 1);
    score += lengthBonus;
    reasons.push(`域名超长（${domain.length} 字符，超过 30）`);
  }

  // URL 结构信号：同一域名内各命中一次，不叠加（多 URL 不重复加分）
  const url = input.urlSignals ?? {};
  if (url.hasIp) {
    score += params.urlIpBonus;
    reasons.push("URL 使用 IP 直连（无域名归属）");
  }
  if (url.hasUserinfo) {
    score += params.urlUserinfoBonus;
    reasons.push("URL 含 userinfo/@ 混淆");
  }
  if (url.hasShortener) {
    score += params.urlShortenerBonus;
    reasons.push("短链域名（真实落点被隐藏）");
  }
  if (url.hasTracking) {
    score += params.urlTrackingBonus;
    reasons.push("URL 含追踪参数");
  }
  if (url.deepPath) {
    score += params.urlDeepPathBonus;
    reasons.push("URL 路径过深（≥4 段）");
  }
  if (url.longQuery) {
    score += params.urlLongQueryBonus;
    reasons.push("URL 查询串超长");
  }
  if (url.nonStandardPort) {
    score += params.urlPortBonus;
    reasons.push("URL 使用非标准端口");
  }

  // 注册年龄评分
  if (input.creationDate) {
    const cutoffYear = params.cutoffYear;
    const y = Number(input.creationDate.slice(0, 4));
    const isPostCutoff = !Number.isNaN(y) && y >= cutoffYear;
    if (isPostCutoff) {
      score += params.postCutoffBonus;
      reasons.push(`域名注册于 ${input.creationDate.slice(0, 10)}（${cutoffYear} 年后）`);
    } else {
      reasons.push(`域名注册于 ${input.creationDate.slice(0, 10)}（${cutoffYear} 年前）`);
    }
  } else if (input.ageUnavailable === "failed") {
    // 已尝试查询但失败（RDAP 无公开数据、网络阻断等）：降为可疑级，避免误报
    score += params.ageUnavailablePenalty;
    reasons.push("年龄查询失败，未能验证注册年龄");
  } else if (input.ageUnavailable === "disabled" || !input.settings.ageQuery.enabled) {
    // 查询压根没开：降为可疑级，避免默认配置下满屏警告
    score += params.ageDisabledPenalty;
    reasons.push("年龄查询未启用，未能验证注册年龄（启用后按新域名从严处理）");
  } else {
    // 查询已启用、无失败标记、又没有日期：仅直接调用纯函数时可能走到，按 treatAsNew 从严
    score += params.postCutoffBonus;
    reasons.push("查不到年龄，按新域名处理（onFailure=treatAsNew）");
  }

  return {
    domain,
    score: Math.min(100, Math.max(0, score)),
    level: levelFromScore(score),
    reasons,
    judgedBy: "score_engine",
    creationDate: input.creationDate,
    sourceKind: source,
  };
}

/** 简单模式：年龄时间线判定。 */
export function scoreSimple(input: ScoringInput): Verdict {
  const params: Required<ScoringParams> = { ...DEFAULT_SCORING, ...(input.settings.scoring ?? {}) };
  const cutoffYear = params.cutoffYear;

  if (input.creationDate) {
    const y = Number(input.creationDate.slice(0, 4));
    const isPreCutoff = !Number.isNaN(y) && y < cutoffYear;
    return {
      domain: input.domain,
      score: isPreCutoff ? 0 : 100,
      level: isPreCutoff ? "trusted" : "critical",
      reasons: [
        isPreCutoff
          ? `域名注册于 ${input.creationDate.slice(0, 10)}（${cutoffYear} 年前）`
          : `域名注册于 ${input.creationDate.slice(0, 10)}（${cutoffYear} 年后）`,
      ],
      judgedBy: "timeline_2023",
      creationDate: input.creationDate,
      sourceKind: "api_query",
    };
  }
  // 查不到 → treatAsNew
  return {
    domain: input.domain,
    score: 100,
    level: "critical",
    reasons: ["查不到年龄，按新域名处理（onFailure=treatAsNew）"],
    judgedBy: "unverifiable",
    sourceKind: "unverifiable",
  };
}

/** 白名单模式。 */
export function scoreWhitelist(input: ScoringInput): Verdict {
  if (input.whitelist.has(input.domain)) {
    return {
      domain: input.domain,
      score: 0,
      level: "trusted",
      reasons: ["白名单域名"],
      judgedBy: "whitelist",
      sourceKind: "whitelist",
    };
  }
  return {
    domain: input.domain,
    score: 100,
    level: "critical",
    reasons: ["不在白名单"],
    judgedBy: "whitelist",
    sourceKind: "unverifiable",
  };
}

/**
 * 顶层路由：先拦截名单，再按模式主逻辑。纯函数。
 * 拦截名单命中时不再评分、不参与模式，直接标红。
 */
export function classify(input: ScoringInput): Verdict {
  // 拦截名单优先级最高，但受该模式 blocklistEnabled 开关控制（每模式独立开关）。
  const blocklistEnabled = input.settings.blocklistEnabled[input.mode];
  if (blocklistEnabled && isBlocklistHit(input)) {
    return {
      domain: input.domain,
      score: 100,
      level: "critical",
      reasons: ["你标记的（拦截名单）"],
      judgedBy: "blocklist",
      sourceKind: "blocklist",
    };
  }

  // 白名单免查：whitelist 模式天然全按名单；normal 模式受 whitelistEnabled.normal 开关控制
  const whitelistBypass =
    input.mode === "whitelist" || (input.mode === "normal" && input.settings.whitelistEnabled.normal);
  if (whitelistBypass && input.whitelist.has(input.domain)) {
    return {
      domain: input.domain,
      score: 0,
      level: "trusted",
      reasons: ["白名单域名"],
      judgedBy: "whitelist",
      sourceKind: "whitelist",
    };
  }

  switch (input.mode) {
    case "whitelist":
      return scoreWhitelist(input);
    case "simple":
      return scoreSimple(input);
    case "normal":
      return scoreNormal(input);
  }
}

/** 按威胁度降序排序。 */
export function sortByThreat(verdicts: Verdict[]): Verdict[] {
  return [...verdicts].sort((a, b) => b.score - a.score);
}