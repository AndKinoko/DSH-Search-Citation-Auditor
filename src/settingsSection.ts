/**
 * 设置面板（client 设置卡片）的 host 半边：
 *  - 声明 citation-auditor 设置命名空间的 schema（schemastery）
 *  - 设置文档 section ↔ 插件 Settings 的双向映射
 *  - 经 installSettingsSection 挂接：卡片写入 → onChange → 落盘 settings.json
 *
 * 设计取舍：插件的 settings.json 仍是唯一真源（Phase 1 的"改完即生效"承诺）。
 * 设置卡片写入经 onChange 回写文件；直接编辑 settings.json 立即生效，
 * 但设置文档的用户层不会反向同步——卡片显示的值以下一次挂载/刷新为准。
 *
 * dsh-settings 是可选服务：宿主没有 settings 服务时本模块整体不激活，
 * 插件照常以文件为配置运行（与 citation_manage 工具等价）。
 */
import Schema from "@deepseek-ai/schemastery";
import type { Context } from "@deepseek-ai/cordis";
import type { Settings } from "./auditor/types.js";
import { DEFAULT_ENFORCEMENT, DEFAULT_SCORING, type EnforcementAction } from "./auditor/types.js";
import { DEFAULT_INJECTION } from "./auditor/injection/types.js";

/** client 可见的扁平 section 形状（设置文档用户层存的就是它）。 */
export interface CitationSettingsSection {
  enabled: boolean;
  mode: Settings["mode"];
  blocklistEnabledWhitelist: boolean;
  blocklistEnabledNormal: boolean;
  blocklistEnabledSimple: boolean;
  whitelistEnabledNormal: boolean;
  ageQueryEnabled: boolean;
  /** 拦截策略：allow=仅提醒，ask=需确认，deny=直接拦截。 */
  enforcementBlocklist: EnforcementAction;
  /** 评分阈值（高级）：设置面板折叠区可调，直接改 settings.json.scoring 即生效。 */
  scoringCutoffYear: number;
  scoringTldTrustBonus: number;
  scoringPatternBonus: number;
  scoringPostCutoffBonus: number;
  scoringUrlIpBonus: number;
  scoringUrlShortenerBonus: number;
  scoringUrlTrackingBonus: number;
  /** 网页内容注入防护（v0.4）：web_fetch 响应正文的注入检测。 */
  injectionEnabled: boolean;
  injectionFuzzy: boolean;
  injectionFuzzyThreshold: number;
  injectionScanMaxBytes: number;
}

/** 设置命名空间：kebab-case，client 侧 settingsScope.bind 用同名。 */
export const SETTINGS_NAMESPACE = "citation-auditor";

/** section 的 schemastery schema（设置面板据此渲染与校验）。 */
export function makeSectionSchema(): Schema<CitationSettingsSection> {
  return Schema.object({
    enabled: Schema.boolean().default(true).description("启用插件（关闭=完全休眠）"),
    mode: Schema.union(["whitelist", "normal", "simple"] as const)
      .default("normal")
      .description("检测模式"),
    blocklistEnabledWhitelist: Schema.boolean().default(true).description("白名单模式下启用拦截名单"),
    blocklistEnabledNormal: Schema.boolean().default(true).description("普通模式下启用拦截名单"),
    blocklistEnabledSimple: Schema.boolean().default(true).description("简单模式下启用拦截名单"),
    whitelistEnabledNormal: Schema.boolean().default(true).description("普通模式白名单免查加速"),
    ageQueryEnabled: Schema.boolean().default(false).description("启用年龄查询片段"),
    enforcementBlocklist: Schema.union(["allow", "ask", "deny"] as const)
      .default(DEFAULT_ENFORCEMENT.blocklist)
      .description("拦截策略（allow=仅提醒，ask=需确认，deny=直接拦截）"),
    scoringCutoffYear: Schema.number().default(DEFAULT_SCORING.cutoffYear).description("注册年份分界线（此年及以后注册加分）"),
    scoringTldTrustBonus: Schema.number().default(DEFAULT_SCORING.tldTrustBonus).description("高风险 TLD 加分"),
    scoringPatternBonus: Schema.number().default(DEFAULT_SCORING.patternBonus).description("连字符/数字模式加分"),
    scoringPostCutoffBonus: Schema.number().default(DEFAULT_SCORING.postCutoffBonus).description("分界线后注册加分"),
    scoringUrlIpBonus: Schema.number().default(DEFAULT_SCORING.urlIpBonus).description("IP 直连加分"),
    scoringUrlShortenerBonus: Schema.number().default(DEFAULT_SCORING.urlShortenerBonus).description("短链域名加分"),
    scoringUrlTrackingBonus: Schema.number().default(DEFAULT_SCORING.urlTrackingBonus).description("追踪参数加分"),
    injectionEnabled: Schema.boolean().default(true).description("网页注入防护：web_fetch 正文命中注入时前置警示块（正文不改）"),
    injectionFuzzy: Schema.boolean().default(false).description("typo 模糊匹配（误报较高，按需开启）"),
    injectionFuzzyThreshold: Schema.number().default(1).description("typo 编辑距离阈值"),
    injectionScanMaxBytes: Schema.number().default(DEFAULT_INJECTION.scanMaxBytes).description("单块扫描上限（字节）"),
  }) as Schema<CitationSettingsSection>;
}

function clampInt(v: unknown, fallback: number, min: number, max: number): number {
  const n = typeof v === "number" && Number.isFinite(v) ? Math.round(v) : fallback;
  return Math.min(max, Math.max(min, n));
}

/** 插件 Settings → 扁平 section（挂载时的 base 层）。 */
export function settingsToSection(s: Settings): CitationSettingsSection {
  const scoring = { ...DEFAULT_SCORING, ...(s.scoring ?? {}) };
  const inj = { ...DEFAULT_INJECTION, ...(s.injection ?? {}) };
  return {
    enabled: s.enabled,
    mode: s.mode,
    blocklistEnabledWhitelist: s.blocklistEnabled.whitelist,
    blocklistEnabledNormal: s.blocklistEnabled.normal,
    blocklistEnabledSimple: s.blocklistEnabled.simple,
    whitelistEnabledNormal: s.whitelistEnabled.normal,
    ageQueryEnabled: s.ageQuery.enabled,
    enforcementBlocklist: s.enforcement?.blocklist ?? DEFAULT_ENFORCEMENT.blocklist,
    scoringCutoffYear: scoring.cutoffYear,
    scoringTldTrustBonus: scoring.tldTrustBonus,
    scoringPatternBonus: scoring.patternBonus,
    scoringPostCutoffBonus: scoring.postCutoffBonus,
    scoringUrlIpBonus: scoring.urlIpBonus,
    scoringUrlShortenerBonus: scoring.urlShortenerBonus,
    scoringUrlTrackingBonus: scoring.urlTrackingBonus,
    injectionEnabled: inj.enabled,
    injectionFuzzy: inj.fuzzy,
    injectionFuzzyThreshold: inj.fuzzyThreshold,
    injectionScanMaxBytes: inj.scanMaxBytes,
  };
}

/** 扁平 section → 插件 Settings（保留不归设置面板管的字段，如 ageQuery.code 与未暴露的 scoring 键）。 */
export function sectionToSettings(section: CitationSettingsSection, current: Settings): Settings {
  const scoring = { ...DEFAULT_SCORING, ...(current.scoring ?? {}) };
  const inj = { ...DEFAULT_INJECTION, ...(current.injection ?? {}) };
  return {
    ...current,
    enabled: section.enabled,
    mode: section.mode,
    blocklistEnabled: {
      whitelist: section.blocklistEnabledWhitelist,
      normal: section.blocklistEnabledNormal,
      simple: section.blocklistEnabledSimple,
    },
    whitelistEnabled: { normal: section.whitelistEnabledNormal },
    ageQuery: { ...current.ageQuery, enabled: section.ageQueryEnabled },
    enforcement: {
      ...current.enforcement,
      blocklist:
        section.enforcementBlocklist === "allow" || section.enforcementBlocklist === "ask" || section.enforcementBlocklist === "deny"
          ? section.enforcementBlocklist
          : (current.enforcement?.blocklist ?? DEFAULT_ENFORCEMENT.blocklist),
    },
    injection: {
      ...inj,
      enabled: section.injectionEnabled,
      fuzzy: section.injectionFuzzy,
      fuzzyThreshold: clampInt(section.injectionFuzzyThreshold, inj.fuzzyThreshold, 1, 2),
      scanMaxBytes: clampInt(section.injectionScanMaxBytes, inj.scanMaxBytes, 4096, 8 * 1024 * 1024),
    },
    scoring: {
      ...scoring,
      cutoffYear: clampInt(section.scoringCutoffYear, scoring.cutoffYear, 2000, 2100),
      tldTrustBonus: clampInt(section.scoringTldTrustBonus, scoring.tldTrustBonus, 0, 100),
      patternBonus: clampInt(section.scoringPatternBonus, scoring.patternBonus, 0, 100),
      postCutoffBonus: clampInt(section.scoringPostCutoffBonus, scoring.postCutoffBonus, 0, 100),
      urlIpBonus: clampInt(section.scoringUrlIpBonus, scoring.urlIpBonus, 0, 100),
      urlShortenerBonus: clampInt(section.scoringUrlShortenerBonus, scoring.urlShortenerBonus, 0, 100),
      urlTrackingBonus: clampInt(section.scoringUrlTrackingBonus, scoring.urlTrackingBonus, 0, 100),
    },
  };
}

/**
 * SettingsForms 上本插件用到的成员（最小面）。
 *
 * 0.2.0 起 dsh-settings 只导出 `SettingsForms` 类（实例挂在 `ctx.settings` 上），
 * 提供 configure / describe / update / replace / mutate。旧代的
 * `installSettingsSection` 与 `settingsNamespace` 在 0.2.0 已彻底移除，
 * 本文件不再保留对它们的兼容分支——`engines.dsh >= 0.2.0-rc.2` 这个门槛
 * 表达的是作者的兼容意图，但截至 0.2.0-rc.2 DSH 侧尚无读取 engines 的实现，
 * 所以真正挡住旧宿主的是 peerDependencies 的版本范围，留着反而是没人会走到的死代码。
 *
 * 这里仍用能力探测（看有没有 configure）而非版本号比较：包版本与 API 代际并非
 * 严格一一对应（rc 通道常有跳版），看有没有那个方法更可靠。
 */
interface SettingsFormsLike {
  configure(presentation: { auto?: boolean }, owner?: unknown): () => void;
}

/**
 * 在 settings 服务存在时接上设置命名空间。可选拳：没有 settings 服务的宿主
 * （纯 CLI 用法）跳过安装，插件仍以 settings.json 为配置运行。
 *
 * 本插件带自己的设置页面（client 的 CitationSettingsCard），所以登记
 * auto:false——告诉 settings 服务别再按 Config schema 自动生成一页。
 * 这里只做「存在性声明」，不接管数据真源——settings.json 始终是唯一真源
 * （见本文件头部的设计取舍），这与 SettingsForms「不维护独立权威值、只投影
 * Loader 配置」的取向一致。
 *
 * 经 unknown 桥接：能力探测发生在运行时，编译期拿不到 SettingsForms 的具体类型
 * （dsh-settings 是 optional peer，类型 import 会让无该包的宿主编译失败）。
 */
export function installSettingsCard(ctx: Context): void {
  ctx.inject(["settings"], (sc) => {
    const forms = (sc as unknown as { settings?: SettingsFormsLike }).settings;
    if (forms === undefined || typeof forms.configure !== "function") {
      // 非预期的 settings 实现（第三方或未来版本）：静默缺席，host 工具不受影响
      return;
    }
    sc.effect(() => {
      try {
        // owner 必须是**插件自身的 fiber**（apply 里拿到的 ctx.fiber）。
        //
        // 此前传的是 sc.fiber，但 ctx.inject(deps, cb) 是 ctx.plugin({inject, apply: cb})
        // 的简写（cordis registry.d.ts:104），会创建一个**子 fiber**——那个子 fiber
        // 永远不是 config-editor 的 entry fiber。而 dsh-settings 的实现是
        //   configure(presentation, owner = this.ctx.fiber) → presentations.set(owner, …)
        //   describe() → presentations.get(entry.fiber)?.auto ?? true
        // 键是 owner、查的是 entry.fiber，两者对不上就永远查不到，autoGenerate 一律
        // 回落 true —— 也就是 auto:false 从未生效，dsh-settings 照样自动生成一页
        // 暴露 statePath 的配置页。无报错、无日志，页面看着还挺合理，所以没人会发现。
        // 不传 schema 与 section：SettingsForms 投影的是插件自己的 Config，
        // 不接受插件自备的表单 schema。
        return forms.configure({ auto: false }, ctx.fiber);
      } catch (err) {
        // 登记失败不再静默：早前的注释说这里只为「同一实例重复登记」兜底，但 owner
        // 换成子 fiber 之后那种情况根本不会发生，于是这个 catch 实际上只会吞掉真
        // 故障（例如未来 SettingsForms 改签名），让插件"看起来在工作"却没做它声称
        // 做的事。至少要能被诊断到。
        (sc as unknown as { logger?: { warn: (m: string) => void } }).logger?.warn?.(
          `citation-auditor: SettingsForms.configure 失败 — ${err instanceof Error ? err.message : String(err)}`,
        );
        return () => {};
      }
    }, "settings.configure citation-auditor");
  });
}
