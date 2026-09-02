/**
 * cache：域名创建日期缓存。存储创建日期本身（不可变事实 → 基本永久有效）；
 * 仅 failed 记录可重试。经 KeyValueStore 持久化。
 */
import type { KeyValueStore } from "../storage.js";

type CacheRecord =
  | { kind: "ok"; source: "API查询" | "缓存"; creationDate: string; at: string }
  | { kind: "failed"; createdAt: string; lastError: string };

const KEY = "cache";

export class WhoIsCache {
  constructor(private readonly storage: KeyValueStore) {}

  private load(): Record<string, CacheRecord> {
    const raw = this.storage.getItem(KEY);
    if (!raw) return {};
    try {
      const o = JSON.parse(raw) as Record<string, CacheRecord>;
      return o && typeof o === "object" ? o : {};
    } catch {
      return {};
    }
  }

  private save(map: Record<string, CacheRecord>): void {
    this.storage.setItem(KEY, JSON.stringify(map));
  }

  /** 返回原始缓存记录（ok / failed）；failed 记录不可复用，由调用方判断。 */
  read(domain: string): CacheRecord | undefined {
    return this.load()[domain];
  }

  /** 记录成功解析的创建日期（不可变事实，已有 ok 记录时保留原值）。 */
  noteOk(domain: string, creationDate: string): void {
    const map = this.load();
    const existing = map[domain];
    // 已有 ok 记录则保留原值不变
    if (existing && existing.kind === "ok") return;
    map[domain] = { kind: "ok", source: "API查询", creationDate, at: new Date().toISOString() };
    this.save(map);
  }

  /** 记录一次失败（允许后续重试）。 */
  noteFailed(domain: string, error: string): void {
    const map = this.load();
    map[domain] = { kind: "failed", createdAt: new Date().toISOString(), lastError: error };
    this.save(map);
  }
}