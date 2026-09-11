/**
 * cache：域名创建日期缓存。存储创建日期本身（不可变事实 → 基本永久有效）；
 * 仅 failed 记录可重试（带 TTL 淘汰，默认 7 天）。经 KeyValueStore 持久化。
 */
import type { KeyValueStore } from "../storage.js";
import type { SourceKind } from "./types.js";

/** failed 记录的 TTL：7 天后自动重试。 */
const FAILED_TTL_MS = 7 * 24 * 60 * 60 * 1000;

type CacheRecord =
  | { kind: "ok"; source: SourceKind; creationDate: string; at: string }
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
    const map = this.load();
    const record = map[domain];
    if (!record) return undefined;
    // failed 记录超过 TTL 则视为不存在（允许重试）
    if (record.kind === "failed") {
      const failedAt = new Date(record.createdAt).getTime();
      if (Date.now() - failedAt > FAILED_TTL_MS) {
        delete map[domain];
        this.save(map);
        return undefined;
      }
    }
    return record;
  }

  /** 记录成功解析的创建日期（不可变事实，已有 ok 记录时保留原值）。 */
  noteOk(domain: string, creationDate: string): void {
    const map = this.load();
    const existing = map[domain];
    // 已有 ok 记录则保留原值不变
    if (existing && existing.kind === "ok") return;
    map[domain] = { kind: "ok", source: "api_query", creationDate, at: new Date().toISOString() };
    this.save(map);
  }

  /** 记录一次失败（允许后续重试）。 */
  noteFailed(domain: string, error: string): void {
    const map = this.load();
    map[domain] = { kind: "failed", createdAt: new Date().toISOString(), lastError: error };
    this.save(map);
  }
}