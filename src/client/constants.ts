/**
 * 客户端共享常量：LEVEL_COLOR、BLOCKLIST_FIELD、MODE_LABEL 等，
 * 避免 FloatWindow.tsx 与 AuditReportCard.tsx 重复定义。
 */
import type { Level } from "../auditor/types.js";
import type { CitationSettingsSection } from "../settingsSection.js";

/** 威胁等级颜色映射。 */
export const LEVEL_COLOR: Record<Level, string> = {
  trusted: "#58a65c",
  suspicious: "#d98a2b",
  warning: "#d9a036",
  critical: "#e05555",
};

/** 模式 → 设置文档里对应"该模式拦截名单开关"的字段名。 */
export const BLOCKLIST_FIELD: Record<CitationSettingsSection["mode"], keyof CitationSettingsSection> = {
  whitelist: "blocklistEnabledWhitelist",
  normal: "blocklistEnabledNormal",
  simple: "blocklistEnabledSimple",
};

/** 模式中文标签。 */
export const MODE_LABEL: Record<CitationSettingsSection["mode"], string> = {
  whitelist: "白名单模式",
  normal: "普通模式",
  simple: "简单模式",
};

/** 等宽字体栈。 */
export const MONO = "ui-monospace, SFMono-Regular, Consolas, 'Courier New', monospace";
