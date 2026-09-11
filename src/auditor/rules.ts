/**
 * rules：名单与设置的读写。数据经 KeyValueStore（每 key 一个独立 JSON 文件）持久化，
 * 用户可直接打开文件查看/编辑，改完即生效（DirectoryStore 按 mtime 热重载）。
 *
 * 名单数据 100% 用户所有，程序只有读写权、没有裁判权；
 * 首次运行写入预写内容（whitelist 预写 wikipedia.org 等权威域名，blocklist 预写 .xyz/.top）。
 * 升级永不覆盖；开关与记录解耦。
 */
import type { ListEntry, Settings, ScoringParams } from "./types.js";
import { DEFAULT_SETTINGS, DEFAULT_SCORING, DEFAULT_ENFORCEMENT } from "./types.js";
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
    if (!raw) return { ...DEFAULT_SETTINGS };
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
        scoring: parsed.scoring ? { ...DEFAULT_SCORING, ...parsed.scoring } : undefined,
        enforcement: parsed.enforcement ? { ...DEFAULT_ENFORCEMENT, ...parsed.enforcement } : undefined,
      };
    } catch {
      return { ...DEFAULT_SETTINGS };
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
    const tld = pslParse(domain).tld;
    if (!tld) return false;
    for (const entry of sets.tlds) {
      const suffix = entry.replace(/^\./, "").toLowerCase();
      if (suffix !== "" && (tld === suffix || tld.endsWith(`.${suffix}`))) return true;
    }
    return false;
  }

  private readList(key: string): ListEntry[] {
    const raw = this.storage.getItem(key);
    if (!raw) return [];
    try {
      const arr = JSON.parse(raw) as ListEntry[];
      return Array.isArray(arr) ? arr.filter((e) => e && typeof e.domain === "string") : [];
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