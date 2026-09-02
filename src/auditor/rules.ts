/**
 * rules：名单与设置的读写。数据经 KeyValueStore（每 key 一个独立 JSON 文件）持久化，
 * 用户可直接打开文件查看/编辑，改完即生效（DirectoryStore 按 mtime 热重载）。
 *
 * 名单数据 100% 用户所有，程序只有读写权、没有裁判权；
 * 首次运行写入预写内容（whitelist 预写 wikipedia.org 等权威域名，blocklist 预写 .xyz/.top）。
 * 升级永不覆盖；开关与记录解耦。
 */
import type { ListEntry, Settings } from "./types.js";
import { DEFAULT_SETTINGS } from "./types.js";
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

  /** 加入白名单（数据立即落盘）。 */
  addToWhitelist(domain: string, reason: string): ListEntry[] {
    return this.addToList(K_WHITE, domain, reason);
  }

  addToBlocklist(domain: string, reason: string): ListEntry[] {
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
   * 用于真实拦截：命中即禁止模型经 web 工具访问该域名。
   */
  blocks(domain: string): boolean {
    const { domains, tlds } = this.blocklistSets();
    if (domains.has(domain)) return true;
    const tld = pslParse(domain).tld;
    if (!tld) return false;
    for (const entry of tlds) {
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

  private addToList(key: string, domain: string, reason: string): ListEntry[] {
    domain = domain.trim().toLowerCase();
    const list = this.readList(key).filter((e) => e.domain !== domain);
    list.push({ domain, reason: reason.trim() || "手动标记", date: new Date().toISOString() });
    this.storage.setItem(key, JSON.stringify(list));
    return list;
  }
}