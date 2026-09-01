/**
 * scorer：三模式评分引擎。纯函数——所有输入显式传入，无 IO、无内部状态。
 *
 * 优先级：拦截名单 > 模式主逻辑（受每模式 blocklistEnabled 开关控制）。
 * 查不到年龄：ageQuery 启用时按 treatAsNew（+50，标红）；
 * 未启用时只记可疑（+20）——没开查询就默认全世界可疑，报表全是噪音。
 * 禁止 treatAsOld。
 */
import { parse as pslParse } from "psl";
import type { Level, Mode, Settings, Verdict } from "./types.js";

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
}

const LEVEL_CRITICAL = 70;
const LEVEL_WARNING = 40;
const LEVEL_SUSPICIOUS = 20;

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

function isPre2023(iso: string): boolean {
  const y = Number(iso.slice(0, 4));
  return !Number.isNaN(y) && y < 2023;
}

/** 普通模式多信号评分。 */
export function scoreNormal(input: ScoringInput): Verdict {
  const reasons: string[] = [];
  const domain = input.domain;
  let score = 0;
  const source = input.creationDate ? "API查询" : "未能验证";

  if (tldBlocked(input)) {
    score += 40;
    reasons.push("TLD 在拦截名单");
  }
  const hyphens = (domain.match(/-/g) ?? []).length;
  const digits = (domain.match(/\d/g) ?? []).length;
  if (hyphens >= 2 || digits >= 3) {
    score += 15;
    reasons.push(`域名含 ${hyphens} 个连字符 / ${digits} 个数字`);
  }
  if (domain.length > 30) {
    score += 3;
    reasons.push("域名超长（>30 字符）");
  }
  if (input.creationDate) {
    if (!isPre2023(input.creationDate)) {
      score += 50;
      reasons.push(`域名注册于 ${input.creationDate.slice(0, 10)}（2023 年后）`);
    } else {
      reasons.push(`域名注册于 ${input.creationDate.slice(0, 10)}（2023 年前）`);
    }
  } else if (input.ageUnavailable === "failed") {
    // 已尝试查询但失败（RDAP 无公开数据、网络阻断等）：降为可疑级，避免误报
    score += 20;
    reasons.push("年龄查询失败，未能验证注册年龄");
  } else if (input.ageUnavailable === "disabled" || !input.settings.ageQuery.enabled) {
    // 查询压根没开：降为可疑级，避免默认配置下满屏警告
    score += 20;
    reasons.push("年龄查询未启用，未能验证注册年龄（启用后按新域名从严处理）");
  } else {
    // 查询已启用、无失败标记、又没有日期：仅直接调用纯函数时可能走到，按 treatAsNew 从严
    score += 50;
    reasons.push("查不到年龄，按新域名处理（onFailure=treatAsNew）");
  }

  return {
    domain,
    score: Math.min(100, score),
    level: levelFromScore(score),
    reasons,
    judgedBy: "score_engine",
    creationDate: input.creationDate,
    sourceKind: source,
  };
}

/** 简单模式：年龄时间线判定。 */
export function scoreSimple(input: ScoringInput): Verdict {
  if (input.creationDate) {
    const pre = isPre2023(input.creationDate);
    return {
      domain: input.domain,
      score: pre ? 0 : 100,
      level: pre ? "trusted" : "critical",
      reasons: [
        pre
          ? `域名注册于 ${input.creationDate.slice(0, 10)}（2023 年前）`
          : `域名注册于 ${input.creationDate.slice(0, 10)}（2023 年后）`,
      ],
      judgedBy: "timeline_2023",
      creationDate: input.creationDate,
      sourceKind: "API查询",
    };
  }
  // 查不到 → treatAsNew
  return {
    domain: input.domain,
    score: 100,
    level: "critical",
    reasons: ["查不到年龄，按新域名处理（onFailure=treatAsNew）"],
    judgedBy: "unverifiable",
    sourceKind: "未能验证",
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
      sourceKind: "白名单",
    };
  }
  return {
    domain: input.domain,
    score: 100,
    level: "critical",
    reasons: ["不在白名单"],
    judgedBy: "whitelist",
    sourceKind: "未能验证",
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
      sourceKind: "拦截名单",
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
      sourceKind: "白名单",
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