/**
 * 持久化：目录化键值存储——每个 key 一个独立 JSON 文件，人可直接打开查看/编辑。
 *
 * 设计规则"改完即生效"：getItem 每次检查文件 mtime，变化即重载（小文件成本可忽略），
 * 外部编辑无需重启插件。写入遵循规范 §3.5.1：同目录临时文件 + fsync + rename 原子发布；
 * 进程内同步调用天然串行（§3.5.2）。
 *
 * 损坏处理：解析失败 → 先把原文件改名备份为 <file>.corrupt-<ts> 再视为空——
 * 绝不允许静默覆盖用户数据；且按 key 拆文件后，单文件损坏只影响该 key。
 */
import { closeSync, existsSync, fsyncSync, mkdirSync, openSync, readFileSync, renameSync, statSync, writeSync } from "node:fs";
import { dirname, join } from "node:path";

export interface KeyValueStore {
  getItem(key: string): string | undefined;
  setItem(key: string, value: string): void;
}

/** 文件损坏时的备份路径（<file>.corrupt-<时间戳>，不覆盖旧备份）。 */
export function corruptBackupPath(file: string): string {
  return `${file}.corrupt-${new Date().toISOString().replace(/[:.]/g, "-")}`;
}

/** 原子写：同目录临时文件 + fsync + rename（Windows 上 rename 同样覆盖已有目标）。 */
export function atomicWrite(file: string, content: string): void {
  mkdirSync(dirname(file), { recursive: true });
  const tmp = `${file}.${process.pid}.tmp`;
  const fd = openSync(tmp, "w");
  try {
    writeSync(fd, content, 0, "utf8");
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  renameSync(tmp, file);
}

export class DirectoryStore implements KeyValueStore {
  readonly #dir: string;
  #cache = new Map<string, { raw: string | undefined; mtimeMs: number }>();

  constructor(dir: string) {
    this.#dir = dir;
    mkdirSync(dir, { recursive: true });
  }

  #fileOf(key: string): string {
    const safe = key.replace(/[^a-zA-Z0-9_-]/g, "_");
    return join(this.#dir, `${safe}.json`);
  }

  getItem(key: string): string | undefined {
    const file = this.#fileOf(key);
    let mtimeMs: number;
    try {
      mtimeMs = statSync(file).mtimeMs;
    } catch {
      this.#cache.set(key, { raw: undefined, mtimeMs: -1 });
      return undefined; // 文件不存在：全新存储
    }
    const cached = this.#cache.get(key);
    if (cached && cached.mtimeMs === mtimeMs) return cached.raw; // 未变化，走缓存
    let raw: string | undefined;
    try {
      raw = readFileSync(file, "utf8");
    } catch {
      raw = undefined;
    }
    if (raw !== undefined) {
      try {
        JSON.parse(raw); // 仅校验，值本身是 JSON 字符串
      } catch {
        // 损坏：备份原件再视为空，绝不止静默覆盖
        try {
          renameSync(file, corruptBackupPath(file));
        } catch {
          // 备份失败也别抛
        }
        raw = undefined;
      }
    }
    this.#cache.set(key, { raw, mtimeMs });
    return raw;
  }

  setItem(key: string, value: string): void {
    const file = this.#fileOf(key);
    atomicWrite(file, value);
    this.#cache.set(key, { raw: value, mtimeMs: statSync(file).mtimeMs });
  }
}

/** 旧版单文件存储（state.json）。仅保留用于迁移读取。 */
export class JsonFileStore implements KeyValueStore {
  readonly #file: string;
  #data: Map<string, string>;

  constructor(file: string) {
    this.#file = file;
    this.#data = JsonFileStore.#load(file);
  }

  getItem(key: string): string | undefined {
    return this.#data.get(key);
  }

  setItem(key: string, value: string): void {
    this.#data.set(key, value);
    atomicWrite(this.#file, JSON.stringify(Object.fromEntries(this.#data), null, 2));
  }

  static #load(file: string): Map<string, string> {
    let raw: string;
    try {
      raw = readFileSync(file, "utf8");
    } catch {
      return new Map();
    }
    try {
      const parsed = JSON.parse(raw) as Record<string, unknown>;
      const map = new Map<string, string>();
      for (const [k, v] of Object.entries(parsed)) {
        if (typeof v === "string") map.set(k, v);
      }
      return map;
    } catch {
      try {
        renameSync(file, corruptBackupPath(file));
      } catch {
        // 同上：备份失败也别抛
      }
      return new Map();
    }
  }
}

/** 旧单文件 state.json 里的 key → 新目录布局文件名。 */
const LEGACY_KEY_MAP: Record<string, string> = {
  "rules/whitelist.json": "whitelist",
  "rules/blocklist.json": "blocklist",
  "rules/settings.json": "settings",
  "cache/whois.json": "cache",
};

/**
 * 把旧版单文件 state.json 拆分迁移到目录布局。
 * 返回迁移出的年龄查询片段代码（供 ageQuery.js 首次生成用）；无旧文件时返回 ""。
 * 迁移完成后旧文件改名 state.json.migrated-<ts>，绝不删除。
 */
export function migrateLegacyState(dir: string): string {
  const legacy = join(dir, "state.json");
  if (!existsSync(legacy)) return "";
  let legacyCode = "";
  try {
    const old = new JsonFileStore(legacy);
    const store = new DirectoryStore(dir);
    for (const [oldKey, newKey] of Object.entries(LEGACY_KEY_MAP)) {
      const raw = old.getItem(oldKey);
      if (raw !== undefined && store.getItem(newKey) === undefined) {
        store.setItem(newKey, raw);
      }
    }
    const settingsRaw = old.getItem("rules/settings.json");
    if (settingsRaw) {
      try {
        const s = JSON.parse(settingsRaw) as { ageQuery?: { code?: string } };
        legacyCode = s.ageQuery?.code ?? "";
      } catch {
        // 设置解析失败就跳过 code 迁移
      }
    }
    renameSync(legacy, `${legacy}.migrated-${new Date().toISOString().replace(/[:.]/g, "-")}`);
  } catch {
    // 无法迁移就保留原样，不动用户文件
  }
  return legacyCode;
}
