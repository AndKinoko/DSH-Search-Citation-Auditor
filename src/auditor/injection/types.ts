/**
 * 网页内容提示词注入检测：领域类型。
 *
 * 与 auditor/ 的域名链（scanner/scorer/report）平行——那是一条业务链，这是第二条。
 * 两者不共享类型：注入检测发生在工具结果边界上，与「引用来源信誉」无关。
 *
 * 设计定位（README「网页内容注入防护」一节有完整说明）：
 * 目的是降低注入成功率 + 让攻击对用户可见，不是杜绝注入。
 */

/**
 * 处置力度。本期只有 "warn" 一个取值。
 *
 * 预留 "redact" / "block" 是刻意的类型层留白：加档位时改本类型与
 * injectionBlock.ts 的分支即可，不必动 detect.ts 的检测内核。
 */
export type InjectionMode = "warn";

/** 命中来源的检测层。0=归一化异常，1=高置信正则，2=结构信号，3=编码解码，4=typo 模糊。 */
export type InjectionLayer = 0 | 1 | 2 | 3 | 4;

export type InjectionKind = "direct" | "structural" | "encoded" | "fuzzy";

export type InjectionSeverity = "high" | "medium" | "low";

/** 注入防护设置。存 settings.json 的 injection 键。 */
export interface InjectionSettings {
  /** 总开关：false = 检测与警示全部旁路。 */
  enabled: boolean;
  /** 处置力度（本期仅 "warn"：在正文前插入警示块，正文一字不改）。 */
  mode: InjectionMode;
  /** 单个文本块扫描上限（字节）；超限截断并记 truncated。 */
  scanMaxBytes: number;
  /** typo 模糊匹配开关。默认 false——开了误报显著上升，会训练用户无视告警。 */
  fuzzy: boolean;
  /** typo 编辑距离阈值（1 或 2；2 的误报不可接受）。 */
  fuzzyThreshold: number;
  /** 单次解码输出上限（字节），防解码炸弹。 */
  decodeMaxBytes: number;
  /** 单份正文的解码候选数上限，超出后停止复检。 */
  decodeMaxCandidates: number;
  /** 不可见字符占比告警阈值（0-1）。 */
  invisibleRatio: number;
}

export const DEFAULT_INJECTION: Required<InjectionSettings> = {
  enabled: true,
  mode: "warn",
  scanMaxBytes: 256 * 1024,
  fuzzy: false,
  fuzzyThreshold: 1,
  decodeMaxBytes: 64 * 1024,
  decodeMaxCandidates: 20,
  invisibleRatio: 0.001,
};

/** 一条命中记录。offset 为归一化文本中的位置，evidence 截断展示。 */
export interface InjectionFinding {
  /** 命中的规则 id（patterns.ts 中定义），便于测试定位与文案映射。 */
  ruleId: string;
  kind: InjectionKind;
  severity: InjectionSeverity;
  layer: InjectionLayer;
  /** 人类可读的规则名（中文），直接进警示块。 */
  label: string;
  /** 命中片段，截断至 120 字符。 */
  evidence: string;
  offset: number;
}

/** 一段文本的检测结果。只承载检测结果，不含任何处置动作。 */
export interface InjectionReport {
  clean: boolean;
  findings: InjectionFinding[];
  /** 是否检出不可见/需归一化的字符（即便无规则命中也算一条 structural 发现）。 */
  normalized: boolean;
  scannedBytes: number;
  truncated: boolean;
}

/** 规则定义：高置信正则或结构信号。 */
export interface InjectionRule {
  id: string;
  /** 中文规则名，进警示块文案。 */
  label: string;
  kind: InjectionKind;
  layer: InjectionLayer;
  severity: InjectionSeverity;
  /** 正则源码（不含 / / 与 g 标志，由 detect.ts 统一加 gi）。 */
  pattern: string;
}

/** 结构信号：非正则的辅助检测。 */
export interface StructuralRule {
  id: string;
  label: string;
  severity: InjectionSeverity;
  /** 结构特征所在的正则；命中后取其上下文做进一步判定。 */
  pattern: string;
  /** 上下文窗口（字符），供 detect.ts 提取证据。 */
  context: number;
  /**
   * 噪声过滤：命中后先经此判定，判定为噪声则丢弃该命中。
   * 真实网页里 `&nbsp;` / `&amp;` / 普通 HTML 注释遍地都是，结构特征必须能
   * 把它们与真正的藏字区分开，否则误报会淹没真告警。
   * 缺省 = 不做噪声过滤（命中即记录，仅在与高置信规则邻近时升级）。
   */
  isNoise?: string;
}

/** 编码载荷的解码结果。 */
export interface DecodedPayload {
  /** 载荷在原文中的位置。 */
  offset: number;
  text: string;
}
