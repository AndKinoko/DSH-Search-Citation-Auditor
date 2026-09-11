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
  }) as Schema<CitationSettingsSection>;
}

function clampInt(v: unknown, fallback: number, min: number, max: number): number {
  const n = typeof v === "number" && Number.isFinite(v) ? Math.round(v) : fallback;
  return Math.min(max, Math.max(min, n));
}

/** 插件 Settings → 扁平 section（挂载时的 base 层）。 */
export function settingsToSection(s: Settings): CitationSettingsSection {
  const scoring = { ...DEFAULT_SCORING, ...(s.scoring ?? {}) };
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
  };
}

/** 扁平 section → 插件 Settings（保留不归设置面板管的字段，如 ageQuery.code 与未暴露的 scoring 键）。 */
export function sectionToSettings(section: CitationSettingsSection, current: Settings): Settings {
  const scoring = { ...DEFAULT_SCORING, ...(current.scoring ?? {}) };
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

export interface SettingsSectionSink {
  /** 当前权威 section（installSettingsSection 的 setSource 接住的）。 */
  (): CitationSettingsSection;
}

/**
 * 在 settings 服务存在时安装设置命名空间。可选拳：没有 settings 服务的宿主
 * （纯 CLI 用法）跳过安装，插件仍以 settings.json 为配置运行。
 */
export function installSettingsCard(
  ctx: Context,
  base: CitationSettingsSection,
  onChange: (section: CitationSettingsSection) => void,
): void {
  ctx.inject(["settings"], () => {
    void import("@deepseek-ai/dsh-settings")
      .then(({ installSettingsSection, settingsNamespace }) => {
        let current: SettingsSectionSink = () => base;
        installSettingsSection<CitationSettingsSection>(
          ctx,
          settingsNamespace(SETTINGS_NAMESPACE),
          makeSectionSchema(),
          base,
          {
            setSource: (source) => {
              current = source;
            },
            onChange: () => {
              onChange(current());
            },
          },
        );
      })
      .catch(() => {
        // dsh-settings 不可用（版本过旧/未装）：设置卡片静默缺席，host 工具不受影响
      });
  });
}
