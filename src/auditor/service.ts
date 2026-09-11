/**
 * Auditor 服务：把纯函数模块组装成可运行的审计闭环。
 * 设计哲学：只检测、只呈现、不拦截，一切处置权归用户。工具是眼镜，不是过滤器。
 */
import { scanDetailed, aggregateDomainSignals } from "./scanner.js";
import { classify, sortByThreat } from "./scorer.js";
import { renderReport, renderSummaryLine } from "./report.js";
import { RuleStore } from "./rules.js";
import { WhoIsCache } from "./cache.js";
import { makeAgeResolver } from "./ageQuery.js";
import type { AgeQueryFile } from "./ageQueryFile.js";
import type { ScanResult, Settings } from "./types.js";
import { DEFAULT_ENFORCEMENT, ENFORCEMENT_LABEL } from "./types.js";
import type { KeyValueStore } from "../storage.js";

export interface AuditOutcome {
  result: ScanResult;
  report: string;
  summary: string | null;
}

export class Auditor {
  readonly rules: RuleStore;
  readonly cache: WhoIsCache;

  constructor(
    private readonly storage: KeyValueStore,
    private readonly ageQueryFile: AgeQueryFile,
  ) {
    this.rules = new RuleStore(storage);
    this.cache = new WhoIsCache(storage);
  }

  init(): void {
    this.rules.ensureSeeded();
  }

  getSettings(): Settings {
    return this.rules.getSettings();
  }

  setMode(mode: Settings["mode"]): Settings {
    const s = this.rules.getSettings();
    s.mode = mode;
    this.rules.saveSettings(s);
    return s;
  }

  setEnabled(enabled: boolean): Settings {
    const s = this.rules.getSettings();
    s.enabled = enabled;
    this.rules.saveSettings(s);
    return s;
  }

  /** 当前年龄查询片段（每次实时读 ageQuery.js，编辑保存即生效）。 */
  getAgeQueryCode(): string {
    return this.ageQueryFile.read();
  }

  get status() {
    const s = this.rules.getSettings();
    return {
      enabled: s.enabled,
      mode: s.mode,
      blocklistEnabled: s.blocklistEnabled[s.mode],
      whitelistCount: this.rules.getWhitelist().length,
      blocklistCount: this.rules.getBlocklist().length,
      ageQueryEnabled: s.ageQuery.enabled && this.ageQueryFile.read().trim() !== "",
      enforcement: s.enforcement?.blocklist ?? DEFAULT_ENFORCEMENT.blocklist,
    };
  }

  /** 扫描 + 评分（最多对每个域名做一次年龄查询，走缓存兜底，带并发上限）。 */
  async audit(text: string): Promise<AuditOutcome> {
    const s = this.rules.getSettings();
    // 总开关关闭 = 完全休眠：立即返回空报表，不扫描、不加载名单、不发任何网络请求
    if (!s.enabled) {
      return {
        result: { urls: [], domains: [], verdicts: [] },
        report: "",
        summary: null,
      };
    }
    const { urls, domains, details } = scanDetailed(text);
    const code = this.ageQueryFile.read(); // 实时读取，编辑 ageQuery.js 即生效
    const resolver = makeAgeResolver({
      code,
      enabled: s.ageQuery.enabled,
      cache: this.cache,
    });

    // 年龄查询并发数：避免一次回复含大量未缓存域名时串行拖长审计时间
    const AGE_QUERY_CONCURRENCY = 4;
    const needsAge = s.mode === "simple" || s.mode === "normal";
    const ageAttempted = s.ageQuery.enabled && code.trim() !== "";

    const creationDates = new Map<string, string>();
    const failedAges = new Set<string>();
    const cacheHits = new Set<string>();
    await mapLimit(domains, AGE_QUERY_CONCURRENCY, async (domain) => {
      if (needsAge && ageAttempted) {
        // 查询前先看一眼缓存：命中且结果一致 → 来源标"缓存"而非"API查询"
        const pre = this.cache.read(domain);
        const cachedOk = pre?.kind === "ok" && typeof pre.creationDate === "string";
        const cd = await resolver(domain);
        if (cd) {
          creationDates.set(domain, cd);
          if (cachedOk && pre.creationDate === cd) cacheHits.add(domain);
        } else {
          failedAges.add(domain); // 查询跑过但没拿到日期（失败/无数据）
        }
      }
    });

    const blockSets = this.rules.blocklistSets();
    const { domains: blockDomains, tlds: blockTlds } = blockSets;
    const whitelist = this.rules.whitelistSet();
    const enforcement = s.enforcement?.blocklist ?? DEFAULT_ENFORCEMENT.blocklist;
    const verdicts = domains.map((domain) => {
      const v = classify({
        domain,
        mode: s.mode,
        settings: s,
        blocklist: blockDomains,
        blockedTlds: blockTlds,
        whitelist,
        creationDate: creationDates.get(domain),
        ageUnavailable: creationDates.has(domain)
          ? undefined
          : ageAttempted && failedAges.has(domain)
            ? "failed"
            : "disabled",
        urlSignals: aggregateDomainSignals(details, domain),
      });
      // scorer 只能标"API查询"（它不认识缓存）；缓存命中的判决在这里改标"缓存"
      if (v.sourceKind === "api_query" && cacheHits.has(domain)) v.sourceKind = "cache";
      // 处置动作：命中拦截名单（精确或 TLD）即按策略标记，否则仅提醒
      v.action = this.rules.blocksWith(blockSets, domain) ? enforcement : "allow";
      return v;
    });
    const ordered = sortByThreat(verdicts);
    return {
      result: { urls, domains, verdicts: ordered },
      report: renderReport(ordered, { enforcement: ENFORCEMENT_LABEL[enforcement] }),
      summary: renderSummaryLine(ordered),
    };
  }
}

/** 带并发上限的 map：单元素失败不中断其他元素的处理。 */
async function mapLimit<T>(
  items: readonly T[],
  concurrency: number,
  fn: (item: T) => Promise<void>,
): Promise<void> {
  const limit = Math.max(1, concurrency);
  const queue = [...items];
  const workers: Promise<void>[] = [];
  for (let i = 0; i < limit && i < queue.length; i++) {
    workers.push((async () => {
      while (queue.length > 0) {
        const item = queue.shift()!;
        try {
          await fn(item);
        } catch {
          // 单个元素失败不中断其他元素的处理
        }
      }
    })());
  }
  await Promise.all(workers);
}