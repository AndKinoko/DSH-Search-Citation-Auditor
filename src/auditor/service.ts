/**
 * Auditor 服务：把纯函数模块组装成可运行的审计闭环。
 * 设计哲学：只检测、只呈现、不拦截，一切处置权归用户。工具是眼镜，不是过滤器。
 *
 * v0.4 补充：以上哲学约束的是**审计链**（scanner → scorer → report），它对
 * 输入文本仍然只读不改。响应侧的注入检测是独立的一条链（auditor/injection/ +
 * injectionBlock.ts），在 tools/post-execute 上、仅对 web_fetch 的结果生效，
 * 且只在正文前面插入警示块——不删、不改任何原文内容。
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
import { DEFAULT_INJECTION } from "./injection/types.js";
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
      // 读**有效值**，不要 `(s.injection ?? DEFAULT_INJECTION)`：getSettings() 的
      // 解析失败分支早前返回裸 DEFAULT_SETTINGS（无 injection 键），于是这里会
      // 报 true 而实际防护整体旁路——界面说谎正是最难排查的那种故障。getSettings()
      // 现已保证 injection 必定成形，这里直接读即可；`=== true` 再兜一层，
      // 避免 undefined 被当成"启用"。
      injectionEnabled: s.injection?.enabled === true,
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
    // 输入硬上限。单次工具调用可以带任意长度的 text，而每个未缓存域名都要起一个
    // Worker（实测 ~7ms，上限 5s），总量与总时长此前都不受约束——一次 64KB 的
    // HTTP body 就能派生约 1000 个线程与约 1000 次出网请求，墙钟可达数分钟，
    // 期间宿主事件循环被反复打断。这里从源头把工作量钉死。
    const MAX_TEXT_CHARS = 64 * 1024;
    const MAX_AGE_DOMAINS = 100;

    const { urls, domains, details } = scanDetailed(text.slice(0, MAX_TEXT_CHARS));
    // 报表仍覆盖**全部**域名（域名数只影响年龄查询这一项网络开销，不影响检测
    // 覆盖面），只有年龄查询取前 N 个候选。
    const ageCandidates = domains.length > MAX_AGE_DOMAINS ? domains.slice(0, MAX_AGE_DOMAINS) : domains;

    const blockSets = this.rules.blocklistSets();
    const { domains: blockDomains, tlds: blockTlds } = blockSets;
    const whitelist = this.rules.whitelistSet();
    const enforcement = s.enforcement?.blocklist ?? DEFAULT_ENFORCEMENT.blocklist;

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

    // 注：审查报告里的 L12（名单内域名仍发年龄查询）**刻意未修**——白名单域名照样
    // 走查询是既有且有测试固定的行为（core.test.ts「首次查询标 API 查询」用的正是预写
    // 白名单里的 github.com）。跳过它会改变已文档化的语义，而该项只是 NIT 级
    // （多花时间、多一次出网），不值得拿行为回归去换。
    const creationDates = new Map<string, string>();
    const failedAges = new Set<string>();
    const cacheHits = new Set<string>();
    await mapLimit(ageCandidates, AGE_QUERY_CONCURRENCY, async (domain) => {
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
      // 处置动作：命中拦截名单（精确或 TLD）**且当前模式启用了拦截名单**才按策略
      // 标记，否则仅提醒。此前这里漏了 blocklistEnabled[mode] 门控，而 classify
      // 有：于是用户在 simple 模式关掉拦截名单后，同一域名既被判 trusted 又被判
      // deny，判决与动作自相矛盾，且与 scorer.ts 的注释相悖。
      const blocklistOn = s.blocklistEnabled[s.mode] === true;
      v.action = blocklistOn && this.rules.blocksWith(blockSets, domain) ? enforcement : "allow";
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