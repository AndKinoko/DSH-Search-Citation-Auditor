/**
 * rules：名单与设置的读写。数据经 KeyValueStore（每 key 一个独立 JSON 文件）持久化，
 * 用户可直接打开文件查看/编辑，改完即生效（DirectoryStore 按 mtime 热重载）。
 *
 * 名单数据 100% 用户所有，程序只有读写权、没有裁判权；
 * 首次运行写入预写内容（whitelist 预写 wikipedia.org 等权威域名，blocklist 预写 .xyz/.top）。
 * 升级永不覆盖；开关与记录解耦。
 */
import type { EnforcementAction, ListEntry, Settings, ScoringParams } from "./types.js";
import { DEFAULT_SETTINGS, DEFAULT_SCORING, DEFAULT_ENFORCEMENT } from "./types.js";
import type { InjectionSettings } from "./injection/types.js";
import { DEFAULT_INJECTION } from "./injection/types.js";
import type { KeyValueStore } from "../storage.js";
import { parse as pslParse } from "psl";

const K_WHITE = "whitelist";
const K_BLOCK = "blocklist";
const K_SETTINGS = "settings";

const PREWRITE_WHITE: ListEntry[] = [
  { domain: "wikipedia.org", reason: "预写：权威百科", date: "2024-01-01T00:00:00Z" },
  { domain: "github.com", reason: "预写：权威代码托管", date: "2024-01-01T00:00:00Z" },
];

const PREWRITE_BLOCK: ListEntry[] = [
  { domain: ".xyz", reason: "预写：垃圾 TLD", date: "2024-01-01T00:00:00Z" },
  { domain: ".top", reason: "预写：垃圾 TLD", date: "2024-01-01T00:00:00Z" },
];

const MODES = ["whitelist", "normal", "simple"] as const;
const ENFORCEMENT_ACTIONS = ["allow", "ask", "deny"] as const;

function isModeValue(v: unknown): v is Settings["mode"] {
  return typeof v === "string" && (MODES as readonly string[]).includes(v);
}

function isEnforcementAction(v: unknown): v is EnforcementAction {
  return typeof v === "string" && (ENFORCEMENT_ACTIONS as readonly string[]).includes(v);
}

/**
 * 评分权重逐键校验。
 *
 * settings.json 由用户手改，任何一个 ScoringParams 键是非数值都会出事：
 * `score += "abc"` 让 score 变成字符串，Math.min/max 再产出 NaN，而
 * levelFromScore 的三个比较对 NaN 全为 false → **返回 "trusted"**（fail-open，
 * 高风险域名被判可信）；`25 + "50"` 则虚高到 100（误报）。JSON.stringify(NaN)
 * 还是 null，违反工具声明的 score: {type:"integer"}。
 * 不合规键一律回落默认值，其余保留。
 */
function sanitizeScoring(input: Partial<ScoringParams>): ScoringParams {
  const out: ScoringParams = { ...DEFAULT_SCORING };
  for (const key of Object.keys(DEFAULT_SCORING) as (keyof ScoringParams)[]) {
    const v = input[key];
    if (typeof v === "number" && Number.isFinite(v)) {
      (out as Record<string, number>)[key] = v;
    }
  }
  return out;
}

/** 注入设置逐键校验：scanMaxBytes / fuzzyThreshold 等数值必须有限且为正。 */
function sanitizeInjection(input: Partial<InjectionSettings> | undefined): InjectionSettings {
  const out: InjectionSettings = { ...DEFAULT_INJECTION };
  if (!input || typeof input !== "object") return out;
  if (typeof input.enabled === "boolean") out.enabled = input.enabled;
  if (typeof input.fuzzy === "boolean") out.fuzzy = input.fuzzy;
  if (typeof input.fuzzyThreshold === "number" && Number.isFinite(input.fuzzyThreshold)) {
    out.fuzzyThreshold = Math.min(2, Math.max(1, Math.round(input.fuzzyThreshold)));
  }
  if (typeof input.scanMaxBytes === "number" && Number.isFinite(input.scanMaxBytes)) {
    out.scanMaxBytes = Math.min(8 * 1024 * 1024, Math.max(4096, Math.round(input.scanMaxBytes)));
  }
  return out;
}

/**
 * 完整默认设置。注入字段必须**显式**给出：DEFAULT_SETTINGS 里它是可选的，
 * 早前的 catch 分支直接展开 DEFAULT_SETTINGS，于是读到的 settings.injection 是
 * undefined，消费方退化成 {} 并整体旁路检测，而界面却仍显示"已启用"。
 * 每个嵌套字段都浅拷贝，避免调用方就地改到模块常量。
 */
function defaultSettings(): Settings {
  return {
    ...DEFAULT_SETTINGS,
    blocklistEnabled: { ...DEFAULT_SETTINGS.blocklistEnabled },
    whitelistEnabled: { ...DEFAULT_SETTINGS.whitelistEnabled },
    ageQuery: { ...DEFAULT_SETTINGS.ageQuery },
    injection: { ...DEFAULT_INJECTION },
  };
}

export class RuleStore {
  constructor(private readonly storage: KeyValueStore) {}

  /** 首次运行初始化：文件不存在才写入预写内容；升级永不覆盖。 */
  ensureSeeded(): void {
    if (this.storage.getItem(K_WHITE) === undefined) {
      this.storage.setItem(K_WHITE, JSON.stringify(PREWRITE_WHITE));
    }
    if (this.storage.getItem(K_BLOCK) === undefined) {
      this.storage.setItem(K_BLOCK, JSON.stringify(PREWRITE_BLOCK));
    }
    if (this.storage.getItem(K_SETTINGS) === undefined) {
      this.storage.setItem(K_SETTINGS, JSON.stringify(DEFAULT_SETTINGS));
    }
  }

  getSettings(): Settings {
    const raw = this.storage.getItem(K_SETTINGS);
    if (!raw) return defaultSettings();
    try {
      const parsed = JSON.parse(raw) as Partial<Settings>;
      return {
        ...DEFAULT_SETTINGS,
        ...parsed,
        enabled: parsed.enabled ?? true,
        blocklistEnabled: { ...DEFAULT_SETTINGS.blocklistEnabled, ...(parsed.blocklistEnabled ?? {}) },
        whitelistEnabled: { ...DEFAULT_SETTINGS.whitelistEnabled, ...(parsed.whitelistEnabled ?? {}) },
        ageQuery: { ...DEFAULT_SETTINGS.ageQuery, ...(parsed.ageQuery ?? {}) },
        onFailure: parsed.onFailure === "treatAsNew" ? "treatAsNew" : DEFAULT_SETTINGS.onFailure,
        // mode / enforcement 逐值校验：settings.json 是给人手改的，一个笔误（"nomral"）
        // 会让 blocklistEnabled[mode] 变 undefined、classify 的 switch 落到无分支处
        // 返回 undefined，再被 service 赋值时抛 TypeError，整个 citation_audit 挂掉。
        mode: isModeValue(parsed.mode) ? parsed.mode : DEFAULT_SETTINGS.mode,
        scoring: parsed.scoring ? sanitizeScoring(parsed.scoring) : undefined,
        enforcement: parsed.enforcement
          ? { blocklist: isEnforcementAction(parsed.enforcement.blocklist) ? parsed.enforcement.blocklist : DEFAULT_ENFORCEMENT.blocklist }
          : undefined,
        injection: sanitizeInjection(parsed.injection),
      };
    } catch {
      // 解析失败也必须走同一个构造器：早前这里直接返回裸 DEFAULT_SETTINGS，而它
      // **没有 injection 键**（该字段可选）。于是注入防护读到 {} → enabled!==true →
      // 整体旁路，而 status.injectionEnabled 用 (s.injection ?? DEFAULT_INJECTION)
      // 仍然报 true —— 防护静默关闭、界面说谎。fail-open 且报告相反事实，比没有
      // 控制更糟。
      return defaultSettings();
    }
  }

  saveSettings(settings: Settings): void {
    this.storage.setItem(K_SETTINGS, JSON.stringify(settings));
  }

  getWhitelist(): ListEntry[] {
    return this.readList(K_WHITE);
  }

  getBlocklist(): ListEntry[] {
    return this.readList(K_BLOCK);
  }

  /** 加入白名单（数据立即落盘）。返回 null 表示格式非法。 */
  addToWhitelist(domain: string, reason: string): ListEntry[] | null {
    return this.addToList(K_WHITE, domain, reason);
  }

  /** 加入拦截名单（数据立即落盘）。返回 null 表示格式非法。 */
  addToBlocklist(domain: string, reason: string): ListEntry[] | null {
    return this.addToList(K_BLOCK, domain, reason);
  }

  removeFromList(kind: "whitelist" | "blocklist", domain: string): boolean {
    const key = kind === "whitelist" ? K_WHITE : K_BLOCK;
    const target = domain.trim().toLowerCase();
    const before = this.readList(key);
    const after = before.filter((e) => e.domain !== target);
    if (after.length === before.length) return false; // 名单里没有，别假报成功
    this.storage.setItem(key, JSON.stringify(after));
    return true;
  }

  /** 解析后的白名单 Set（用于纯函数 scorer）。 */
  whitelistSet(): Set<string> {
    return new Set(this.getWhitelist().map((e) => e.domain));
  }

  /** 解析后的拦截名单 Set + 其中 TLD 的 Set。 */
  blocklistSets(): { domains: Set<string>; tlds: Set<string> } {
    const domains = new Set<string>();
    const tlds = new Set<string>();
    for (const e of this.getBlocklist()) {
      if (e.domain.startsWith(".")) tlds.add(e.domain);
      else domains.add(e.domain);
    }
    return { domains, tlds };
  }

  /**
   * 域名是否命中拦截名单（精确域名或 TLD 后缀命中）。
   * 用于真实拦截：命中即按处置策略阻止或提醒模型经 web 工具访问该域名。
   */
  blocks(domain: string): boolean {
    return this.blocksWith(this.blocklistSets(), domain);
  }

  /** 用已解析的名单集合判定（service 循环内复用，避免重复读盘）。 */
  blocksWith(sets: { domains: Set<string>; tlds: Set<string> }, domain: string): boolean {
    if (sets.domains.has(domain)) return true;
    // 点号条目要分两类，否则一大类用户输入会变成**永远匹配不到的死条目**：
    //   - 纯 TLD（".xyz"）→ 与公共后缀比对，原有语义；
    //   - ".evil.com" 这种「域 + 其子域」写法（hosts 文件 / adblock / uBlock 的标准
    //     语法）→ 必须与**完整主机**比对。此前它只被拿去和 tld 比，而
    //     pslParse("a.evil.com").tld === "com"，于是永远不等于，拦不到任何东西，
    //     而 addToList 照收不误、工具还回报"已加入"。
    for (const entry of sets.tlds) {
      const suffix = entry.replace(/^\./, "").toLowerCase();
      if (suffix === "") continue;
      if (suffix.includes(".")) {
        if (domain === suffix || domain.endsWith(`.${suffix}`)) return true;
        continue;
      }
      const tld = pslParse(domain).tld;
      if (tld && (tld === suffix || tld.endsWith(`.${suffix}`))) return true;
    }
    return false;
  }

  private readList(key: string): ListEntry[] {
    const raw = this.storage.getItem(key);
    if (!raw) return [];
    try {
      const arr = JSON.parse(raw) as ListEntry[];
      if (!Array.isArray(arr)) return [];
      // 归一化：手改名单文件时留下的大小写/空白差异会让条目**永不匹配**，而且
      // removeFromList 按精确串删不掉——用户只能继续手工编辑文件才能移除。
      const out: ListEntry[] = [];
      const seen = new Set<string>();
      for (const e of arr) {
        if (!e || typeof e.domain !== "string") continue;
        const domain = e.domain.trim().toLowerCase();
        if (domain === "" || seen.has(domain)) continue;
        seen.add(domain);
        out.push(domain === e.domain ? e : { ...e, domain });
      }
      return out;
    } catch {
      return [];
    }
  }

  private addToList(key: string, domain: string, reason: string): ListEntry[] | null {
    domain = domain.trim().toLowerCase();
    // 基本格式校验：空字符串直接拒绝；TLD 条目必须以 . 开头，普通域名必须包含 .
    if (!domain) return null;
    if (domain.startsWith(".")) {
      // TLD 条目：去掉前缀后不能为空
      if (domain.length < 2) return null;
      // TLD 条目不允许包含空格、控制字符等非法字符
      if (/[^\x20-\x7e]/.test(domain) || /\s/.test(domain)) return null;
    } else if (!domain.includes(".")) {
      // 普通域名必须包含点号
      return null;
    } else {
      // 普通域名不允许包含空格、控制字符、@/#/? 等非法字符
      if (/[^\x20-\x7e]/.test(domain) || /[\s@#?]/.test(domain)) return null;
    }
    const list = this.readList(key).filter((e) => e.domain !== domain);
    list.push({ domain, reason: reason.trim() || "手动标记", date: new Date().toISOString() });
    this.storage.setItem(key, JSON.stringify(list));
    return list;
  }
}