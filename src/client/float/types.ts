/**
 * 悬浮窗子组件共享类型。
 */
import type { Level, EnforcementAction } from "../../auditor/types.js";
import type { CitationSettingsSection } from "../../settingsSection.js";

/** /api/citation-auditor/audit 负载里的单条判决（含按钮状态机需要的名单隶属）。 */
export interface AuditVerdict {
  domain: string;
  score: number;
  level: Level;
  reasons: string[];
  sourceKind: string;
  action?: EnforcementAction;
  creationDate?: string;
  inWhitelist: boolean;
  inBlocklist: boolean;
}

/** /api/citation-auditor/audit 的负载。 */
export interface AuditData {
  ok: boolean;
  enabled: boolean;
  mode: CitationSettingsSection["mode"];
  blocklistEnabled: boolean;
  enforcement?: EnforcementAction;
  summary: string;
  verdicts: AuditVerdict[];
}

/** /api/citation-auditor/status 的负载（设置视图数据）。 */
export interface StatusData {
  ok: boolean;
  settings: CitationSettingsSection;
  counts: { whitelist: number; blocklist: number };
  files: Record<string, string>;
  ageQueryReady: boolean;
}

/** 弹窗描述：标题 + 正文 + 按钮组。 */
export interface ModalSpec {
  title: string;
  body: string;
  buttons: { label: string; onClick: () => void }[];
}

/** 悬浮窗位置：right/bottom 锚定（窗口缩放时天然贴边）。 */
export interface FloatPos {
  right: number;
  bottom: number;
}
