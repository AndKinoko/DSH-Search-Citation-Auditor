/**
 * 检测编排：归一化 → 高置信正则 → 结构信号 → 解码后复检 → 可选 typo 模糊。
 *
 * 四层里第 3 层（解码复检）是胜负手：攻击者最省事的绕过就是编码，明文正则
 * 一个都不中，解开就中招。OWASP 明确把「解码可疑内容再检查」列为远程内容
 * 消毒的标准动作。
 *
 * 纯函数、同步、零 IO（解码用内置 Buffer，不联网、不起 worker）。
 * 解码有硬上限（长度 + 候选数 + 时间），防解码炸弹。
 */
import { normalize, hasInvisibleInsideWord } from "./normalize.js";
import {
  ALL_HIGH_CONFIDENCE_RULES,
  STRUCTURAL_RULES,
  FUZZY_KEYWORDS,
} from "./patterns.js";
import {
  DEFAULT_INJECTION,
  type DecodedPayload,
  type InjectionFinding,
  type InjectionReport,
  type InjectionSettings,
  type StructuralRule,
} from "./types.js";

/** 证据片段的最大展示长度。 */
const EVIDENCE_MAX = 120;

/** 结构信号只有在窗口内也命中高置信规则时才升级为告警（见 §3.5 组合判定）。 */
const STRUCTURAL_COMBO_WINDOW = 400;

/** 预编译的高置信规则正则（模块级只编译一次，per-request 零编译开销）。 */
const COMPILED_HIGH = ALL_HIGH_CONFIDENCE_RULES.map((rule) => ({
  ...rule,
  re: new RegExp(rule.pattern, "gi"),
}));

const COMPILED_STRUCTURAL: readonly (StructuralRule & { re: RegExp })[] = STRUCTURAL_RULES.map(
  (rule) => ({ ...rule, re: new RegExp(rule.pattern, "gi") }),
);

/** 归一化异常本身的 ruleId（不是 patterns.ts 里的正则规则，故不进规则表）。 */
const NORMALIZE_ANOMALY_RULE = "norm-anomaly";
/** 不可见字符夹在单词内部的 ruleId。 */
const HIDDEN_IN_WORD_RULE = "hidden-in-word";
/** 正文被 scanMaxBytes 截断的 ruleId：截断本身必须可定性，否则上限之外是盲区。 */
const SCAN_TRUNCATED_RULE = "scan-truncated";

/** 截断证据并压成单行，避免警示块被长片段撑开。 */
function evidenceOf(text: string, start: number, length: number): string {
  const slice = text.slice(start, start + length).replace(/\s+/g, " ").trim();
  return slice.length > EVIDENCE_MAX ? `${slice.slice(0, EVIDENCE_MAX)}…` : slice;
}

/**
 * Damerau-Levenshtein 距离（optimal string alignment，滚动数组 O(min) 空间）。
 *
 * 为什么不是普通 Levenshtein：typoglycemia 的定义就是「首尾保留、中间字母
 * **换位**」——`ignroe` 是 `ignore` 把 n/r 对调。用普通 Levenshtein 算这个
 * 换位要 2 步，阈值 1 永远抓不到 OWASP 点名的那个手法。加 OSA 换位转移后是 1 步。
 *
 * @returns 距离；超过 max 时返回 max+1（提前退出，调用方只关心「是否超阈值」）。
 */
export function levenshtein(a: string, b: string, max: number): number {
  if (a === b) return 0;
  if (Math.abs(a.length - b.length) > max) return max + 1;
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;
  let prev2 = new Array<number>(b.length + 1).fill(0);
  let prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  let curr = new Array<number>(b.length + 1);
  for (let i = 1; i <= a.length; i++) {
    curr[0] = i;
    let rowMin = curr[0]!;
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      let v = Math.min(curr[j - 1]! + 1, prev[j]! + 1, prev[j - 1]! + cost);
      // OSA 转移：相邻换位一步完成
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        v = Math.min(v, prev2[j - 2]! + 1);
      }
      curr[j] = v;
      if (v < rowMin) rowMin = v;
    }
    if (rowMin > max) return max + 1; // 整行已超阈值，提前退出
    [prev2, prev, curr] = [prev, curr, prev2];
  }
  return prev[b.length]!;
}

/**
 * typo 模糊匹配（OWASP typoglycemia）。
 *
 * 关键约束：首尾字母必须相同。typoglycemia 的定义就是「首尾保留、中间乱序」，
 * 这条约束砍掉了绝大多数误报——`the`/`then`、`form`/`from` 的首尾不同，直接排除。
 * 长度必须相等或差 1（否则一个字里塞两个词，不是 typo）。
 */
function detectFuzzy(text: string, threshold: number): InjectionFinding[] {
  const findings: InjectionFinding[] = [];
  const seen = new Set<string>();
  const wordRe = /[a-z]{4,}/gi;
  for (const m of text.matchAll(wordRe)) {
    const word = m[0].toLowerCase();
    const offset = m.index ?? 0;
    for (const kw of FUZZY_KEYWORDS) {
      if (word === kw) continue; // 正常词不算
      if (Math.abs(word.length - kw.length) > threshold) continue;
      if (word[0] !== kw[0] || word[word.length - 1] !== kw[kw.length - 1]) continue;
      // 只有当该词的其余上下文也像一条注入指令时才报：单看一个错拼词没意义
      if (levenshtein(word, kw, threshold) > threshold) continue;
      const key = `${word}:${kw}`;
      if (seen.has(key)) continue;
      seen.add(key);
      findings.push({
        ruleId: "typo-glossolalia",
        kind: "fuzzy",
        severity: "medium",
        layer: 4,
        label: `字形打乱疑似注入（${word} ≈ ${kw}）`,
        evidence: evidenceOf(text, offset, word.length),
        offset,
      });
    }
  }
  return findings;
}

/** Base64 候选：长串 + 合法字符集 + 长度可被 4 整除（或允许无填充）。 */
const BASE64_CANDIDATE_RE = /[A-Za-z0-9+/]{40,}={0,2}/g;
/** hex 候选：0x 前缀或纯 hex 串。 */
const HEX_CANDIDATE_RE = /(?:0[xX])?[0-9a-fA-F]{40,}/g;
/**
 * URL-safe Base64 候选：`-`/`_` 替代 `+`/`/`。这类串不是合法标准 Base64，
 * Buffer.from 会静默丢弃非法字符导致解出乱码，故须显式还原后再解。
 */
const BASE64URL_CANDIDATE_RE = /[A-Za-z0-9_-]{40,}={0,2}/g;
/**
 * Base32 候选：RFC 4648 字母表（A-Z + 2-7），大小写不敏感。
 * 长度需 ≥40 才是载荷量级；`=` 填充可有可无。
 */
const BASE32_CANDIDATE_RE = /(?:[A-Za-z2-7]{8,}[=]{0,6}\s?){5,}/g;
/**
 * 百分号编码候选：连续 %XX 转义，≥6 个即视为整段载荷
 * （单个 %20 是普通 URL 编码，遍布全网，不能算信号）。
 */
const PERCENT_CANDIDATE_RE = /(?:%[0-9a-fA-F]{2}){6,}/g;
/**
 * UTF-16 载荷特征：ASCII 文本按 UTF-16 编码后，每两个字节里有一个是 0x00。
 * 直接以 latin1 读入会得到 "i\0g\0n\0o\0r\0e\0..." 这种形态——
 * 这是非 UTF-8 编码绕过里最常见的一类（尤其是 UTF-16LE 原文粘贴）。
 */
const UTF16LE_CANDIDATE_RE = /(?:[\x20-\x7e]\x00){8,}/g;
const UTF16BE_CANDIDATE_RE = /(?:\x00[\x20-\x7e]){8,}/g;

/** 可打印 ASCII 占比阈值：低于此值视为二进制数据而非注入载荷。 */
const PRINTABLE_RATIO_MIN = 0.85;

/**
 * 从 UTF-16 字节流里取出文本：小端取偶数位、大端取奇数位。
 *
 * UTF-16 的 ASCII 区间每个码元是 [字符, 0x00]（LE）或 [0x00, 字符]（BE），
 * 所以每隔一个字节取一个就是原文。UTF-8 编码里 0x00 是独立控制符，
 * 真文本不会这样交替出现——故这个判据本身就足以确认是 UTF-16 载荷。
 */
function stripNuls(buf: Buffer, bigEndian: boolean): string {
  const out: number[] = [];
  for (let i = 0; i + 1 < buf.length; i += 2) out.push(bigEndian ? buf[i + 1]! : buf[i]!);
  return Buffer.from(out).toString("latin1");
}

/** 逐码点统计可打印占比（ASCII 可见 + 常见空白）。 */
function printableRatio(decoded: string): number {
  if (decoded.length === 0) return 0;
  let printable = 0;
  for (const ch of decoded) {
    const cp = ch.codePointAt(0) ?? 0;
    if ((cp >= 0x20 && cp <= 0x7e) || cp === 0x09 || cp === 0x0a || cp === 0x0d) printable += 1;
  }
  return printable / decoded.length;
}

/**
 * Base32 解码（RFC 4648）。返回 latin1 字符串；出现非法字符时返回 null。
 *
 * 填充可省：RFC 4648 允许省略尾部 `=`，实际输出长度也不总对齐到 8 的倍数。
 * 故不做 mod 8 校验，只在遇到字母表外字符时失败——末尾不足 5 位的残余
 * 自然丢弃（不足一字节，不构成有效载荷）。
 */
function decodeBase32(input: string): string | null {
  const clean = input.replace(/=+$/, "").replace(/\s+/g, "").toUpperCase();
  if (clean.length === 0) return null;
  const out: number[] = [];
  let bits = 0;
  let acc = 0;
  for (const ch of clean) {
    const v = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".indexOf(ch);
    if (v === -1) return null;
    acc = (acc << 5) | v;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((acc >> bits) & 0xff);
    }
  }
  if (out.length === 0) return null;
  return Buffer.from(out).toString("latin1");
}

/** 百分号解码（URL decoding）。非法转义按原样保留，不抛。 */
function decodePercent(input: string): string {
  return input.replace(/%([0-9a-fA-F]{2})/g, (_m, hex: string) => String.fromCharCode(Number.parseInt(hex, 16)));
}

/**
 * 保守的部分解码：把「嵌入在明文里的编码片段」就地还原，拼出解码版全文。
 *
 * 与 decodeCandidates 的分工：后者找的是**整段被包起来**的载荷（Base64、hex、
 * Base32），解出来自成一句；这里处理的是**只藏了词、句子还在**的情况——
 * 百分号编码、UTF-16 原文字面量。它们的载荷单独看没有语义，必须放回句子
 * 才能让第 1 层规则匹配。
 *
 * 只做两种解码且都要求「原串确实含该形态」，否则返回原串（调用方靠
 * 返回值是否 === 原串判断有无变化）。
 */
function decodePartially(text: string): string {
  let out = text;
  // 百分号：解码整段高密度转义，但不碰零散的 %20/%2F。
  // 判据是"连续转义 ≥ 6 个"——单个 %20 在真实 URL 里遍地都是，解它没有意义；
  // 而整句被编码时 %XX 会连续出现几十次，一眼可辨。
  out = out.replace(/(?:%[0-9a-fA-F]{2}){6,}/g, (seg) => decodePercent(seg));
  // UTF-16LE/BE 原文字面量：每两个字符取一个
  //
  // 解码后**必须折叠空白**：normalize() 的空白折叠发生在解码之前，而 NUL 字节能
  // 存活那一步，于是这里会凭空生成一长串原始正文里根本不存在的空格。第 3 层把它
  // 与原文拼成 combined 后送进全部约 40 条高置信正则——不折叠就等于给攻击者一个
  // 「纯空格」载荷直达正则引擎的通道（曾致 tool-output-hijack 多项式回溯，
  // 1.6 KB 输入阻塞宿主事件循环 29 秒）。
  out = out.replace(/(?:[\x20-\x7e]\x00){4,}/gu, (seg) =>
    foldDecodedWhitespace(seg.replace(/(..)/gu, (_p, pair: string) => pair[0] ?? "")),
  );
  out = out.replace(/(?:\x00[\x20-\x7e]){4,}/gu, (seg) =>
    foldDecodedWhitespace(seg.replace(/(..)/gu, (_p, pair: string) => pair[1] ?? "")),
  );
  return out;
}

/** 解码产物的空白折叠：长空白串塌成单空格，使下游正则的空白量词保持线性。 */
function foldDecodedWhitespace(s: string): string {
  return s.replace(/\s+/g, " ");
}

/**
 * 提取并解码候选载荷。
 * 硬上限三重：候选数、单次解码字节数、可打印占比——任一不满足即丢弃。
 * 解码结果**只喂给高置信正则**，不再递归解码（防解码炸弹）。
 *
 * 覆盖的编码族：标准/URL-safe Base64、hex、Base32、百分号（URL encoding）、
 * UTF-16LE/BE 原文。UTF-16 之所以值得单独一路：它不是"被包起来"而是
 * "字形本身就是 16 位"——文本里直接可见 i\0g\0n\0o\0r\0e，不走任何编码器。
 */
export function decodeCandidates(
  text: string,
  opts: { maxCandidates: number; maxBytes: number },
): { payloads: DecodedPayload[]; truncated: boolean } {
  const payloads: DecodedPayload[] = [];
  let truncated = false;

  /** 统一的入库闸门：候选数 / 字节数 / 可打印占比三项硬限。 */
  const admit = (offset: number, decoded: string): void => {
    if (payloads.length >= opts.maxCandidates) {
      truncated = true;
      return;
    }
    if (decoded.length === 0) return;
    if (decoded.length > opts.maxBytes) {
      truncated = true;
      return;
    }
    if (printableRatio(decoded) < PRINTABLE_RATIO_MIN) return;
    payloads.push({ offset, text: decoded });
  };

  const considerBase64 = (offset: number, text0: string): void => {
    let buf: Buffer;
    try {
      buf = Buffer.from(text0, "base64");
    } catch {
      return;
    }
    if (buf.byteLength > opts.maxBytes) {
      truncated = true;
      return;
    }
    // UTF-16 载荷的字节流里每个 ASCII 字符都跟一个 0x00，可打印占比只有 ~0.5，
    // 直接按 utf8 解读会被占比阈值挡掉。先试 utf8，占比不达标再试 UTF-16 还原。
    const asUtf8 = buf.toString("utf8");
    if (printableRatio(asUtf8) >= PRINTABLE_RATIO_MIN) {
      admit(offset, asUtf8);
      return;
    }
    if (buf.byteLength % 2 === 0) {
      const le = stripNuls(buf, false);
      if (printableRatio(le) >= PRINTABLE_RATIO_MIN) {
        admit(offset, le);
        return;
      }
      const be = stripNuls(buf, true);
      if (printableRatio(be) >= PRINTABLE_RATIO_MIN) admit(offset, be);
    }
  };

  for (const m of text.matchAll(BASE64_CANDIDATE_RE)) {
    const raw = m[0].replace(/=+$/, "");
    // 长度不是 4 的倍数时 Buffer.from 会静默截断，先按无填充长度校验
    if (raw.length % 4 === 1) continue;
    considerBase64(m.index ?? 0, raw);
  }

  // URL-safe Base64：先还原成标准字母表再解。须排除已被上面捞走的纯字母数字串，
  // 否则同一段会被解两次（第二次得到乱码，浪费候选额度）。
  for (const m of text.matchAll(BASE64URL_CANDIDATE_RE)) {
    if (!/[_-]/.test(m[0])) continue; // 无 url-safe 特征 = 已由标准分支处理
    const restored = m[0].replace(/-/g, "+").replace(/_/g, "/");
    const raw = restored.replace(/=+$/, "");
    if (raw.length % 4 === 1) continue;
    considerBase64(m.index ?? 0, raw);
  }

  for (const m of text.matchAll(HEX_CANDIDATE_RE)) {
    if (payloads.length >= opts.maxCandidates) {
      truncated = true;
      break;
    }
    const body = m[0].replace(/^0[xX]/, "");
    if (body.length % 2 !== 0) continue;
    let decoded: string;
    try {
      decoded = Buffer.from(body, "hex").toString("utf8");
    } catch {
      continue;
    }
    admit(m.index ?? 0, decoded);
  }

  for (const m of text.matchAll(BASE32_CANDIDATE_RE)) {
    const decoded = decodeBase32(m[0]);
    if (decoded !== null) admit(m.index ?? 0, decoded);
  }

  for (const m of text.matchAll(PERCENT_CANDIDATE_RE)) {
    admit(m.index ?? 0, decodePercent(m[0]));
  }

  // UTF-16：文本里以 "i\0g\0n\0..." 形态直接可见，不经任何编码器。
  // latin1 读入后每两个字符是一个 UTF-16 码元（小端即"字符在前 0x00 在后"），
  // 故 LE 取偶数位、BE 取奇数位即可还原原文。
  // 注意：不要用 swap16 + toString("utf8")——那会把字节交换两次，反而解出乱码。
  for (const m of text.matchAll(UTF16LE_CANDIDATE_RE)) {
    admit(m.index ?? 0, m[0].replace(/(..)/gu, (_p, pair: string) => pair[0] ?? ""));
  }
  for (const m of text.matchAll(UTF16BE_CANDIDATE_RE)) {
    admit(m.index ?? 0, m[0].replace(/(..)/gu, (_p, pair: string) => pair[1] ?? ""));
  }

  return { payloads, truncated };
}

/**
 * 噪声过滤：良性 HTML 注释。
 *
 * 真实页面里 `<!-- build: 123 -->`、`<!--[if IE]>`、版权行遍地都是。
 * 判据：注释体里没有注入词，且形态像标记——短，或以条件注释/常见标记开头。
 * 只在 detect.ts 实现，因为需要访问已编译的高置信规则。
 */
function isBenignComment(match: string): boolean {
  const body = match.replace(/^<!--/, "").replace(/-->$/, "").trim();
  if (body === "") return true;
  if (hasHighConfidenceNear(body, 0, body.length + 1)) return false; // 注释里有注入词
  // 条件注释 / 短注释 / 纯标记行
  if (body.length <= 80) return true;
  if (/^(?:\[if|\[endif\]|!|build|built|generated|version|copyright|\(c\))/i.test(body)) return true;
  return false;
}

/** 结构信号规则 → 噪声过滤器。缺省 = 不过滤。 */
const STRUCTURAL_NOISE: Record<string, (match: string) => boolean> = {
  "benign-comment": isBenignComment,
};

/** 某处附近是否有高置信规则命中（用于结构信号的组合判定）。 */
function hasHighConfidenceNear(text: string, center: number, window: number): boolean {
  const from = Math.max(0, center - window);
  const slice = text.slice(from, center + window);
  return COMPILED_HIGH.some((rule) => {
    rule.re.lastIndex = 0;
    return rule.re.test(slice);
  });
}

/**
 * 检测一段文本里的提示词注入。
 * @param raw 原始文本（web_fetch 的 TextBlock 内容）。
 * @param settings 注入设置；缺字段走 DEFAULT_INJECTION 补齐。
 * @returns 检测报告。clean=true 表示无命中。
 */
export function detectInjection(raw: string, settings?: Partial<InjectionSettings>): InjectionReport {
  const s = { ...DEFAULT_INJECTION, ...(settings ?? {}) };
  const findings: InjectionFinding[] = [];

  // 扫描上限：超限截断。截断本身是事实，记进报告。
  const bytes = Buffer.byteLength(raw, "utf8");
  const truncated = bytes > s.scanMaxBytes;
  let text = raw;
  if (truncated) {
    text = Buffer.from(raw, "utf8").subarray(0, s.scanMaxBytes).toString("utf8");
    // 上限可能切在多字节字符中间，留一个 U+FFFD；顺带也堵掉"用填充把攻击语句
    // 顶到边界、靠这个残字符吞掉首字母"的小把戏。
    if (text.endsWith("�")) text = text.slice(0, -1);
  }

  // 截断必须**独立成一条发现**：否则攻击者只要在攻击语句前垫够无害正文把它顶到
  // 上限之外，报告就会是 { clean:true, findings:0, truncated:true }——而
  // applyInjectionNotice 只看 clean，于是 changed:false 直接放行，截断这个事实
  // 永远到不了用户眼前。padding 完全由攻击者控制，这是绕过而非降级。
  if (truncated) {
    findings.push({
      ruleId: SCAN_TRUNCATED_RULE,
      kind: "structural",
      severity: "medium",
      layer: 0,
      label: `正文超出扫描上限（${s.scanMaxBytes} 字节），仅扫描了开头一段`,
      evidence: `已扫描 ${s.scanMaxBytes} / ${bytes} 字节，超出部分未检测`,
      offset: 0,
    });
  }

  if (text.trim() === "") {
    return { clean: true, findings, normalized: false, scannedBytes: 0, truncated };
  }

  // ---- 第 0 层：归一化（同时是信号源）----
  const norm = normalize(text);
  const n = norm.text;

  if (norm.hadInvisible || norm.hadSuspiciousEntities) {
    findings.push({
      ruleId: NORMALIZE_ANOMALY_RULE,
      kind: "structural",
      severity: norm.invisibleRatio > s.invisibleRatio ? "medium" : "low",
      layer: 0,
      label:
        norm.invisibleCount > 0
          ? `正文含 ${norm.invisibleCount} 个不可见/零宽字符`
          : `正文含 ${norm.suspiciousEntityCount} 处 HTML 实体编码的字符`,
      evidence:
        norm.invisibleCount > 0
          ? `不可见字符 ${norm.invisibleCount} 个`
          : `HTML 实体 ${norm.suspiciousEntityCount} 处`,
      offset: 0,
    });
  }

  // 不可见字符夹在单词内部：比"页面含零宽字符"严重得多，是定向藏字的直接证据
  if (norm.hadInvisible && hasInvisibleInsideWord(text)) {
    findings.push({
      ruleId: HIDDEN_IN_WORD_RULE,
      kind: "structural",
      severity: "high",
      layer: 0,
      label: "不可见字符夹在单词内部（定向藏字）",
      evidence: evidenceOf(text, 0, 60),
      offset: 0,
    });
  }

  // ---- 第 1 层：高置信正则 ----
  for (const rule of COMPILED_HIGH) {
    rule.re.lastIndex = 0;
    for (const m of n.matchAll(rule.re)) {
      findings.push({
        ruleId: rule.id,
        kind: "direct",
        severity: rule.severity,
        layer: 1,
        label: rule.label,
        evidence: evidenceOf(n, m.index ?? 0, m[0].length),
        offset: m.index ?? 0,
      });
    }
  }

  // ---- 第 2 层：结构信号（永不单独定性，需与高置信规则邻近才升级）----
  for (const rule of COMPILED_STRUCTURAL) {
    rule.re.lastIndex = 0;
    const noiseFilter = rule.isNoise !== undefined ? STRUCTURAL_NOISE[rule.isNoise] : undefined;
    for (const m of n.matchAll(rule.re)) {
      if (noiseFilter !== undefined && noiseFilter(m[0])) continue; // 良性结构，丢弃
      const offset = m.index ?? 0;
      const combined = hasHighConfidenceNear(n, offset, STRUCTURAL_COMBO_WINDOW);
      findings.push({
        ruleId: rule.id,
        kind: "structural",
        // 组合命中升级为 high，单独出现保持 medium（仅记录，不定性）
        severity: combined ? "high" : rule.severity,
        layer: 2,
        label: combined ? `${rule.label}（内含注入指令）` : rule.label,
        evidence: evidenceOf(n, offset, m[0].length + rule.context),
        offset,
      });
    }
  }

  // ---- 第 3 层：解码后复检 ----
  // 用 textForDecode（未折叠重复字符）提取载荷，见 NormalizeResult.textForDecode
  const { payloads, truncated: decodeTruncated } = decodeCandidates(norm.textForDecode, {
    maxCandidates: s.decodeMaxCandidates,
    maxBytes: s.decodeMaxBytes,
  });
  for (const payload of payloads) {
    for (const rule of COMPILED_HIGH) {
      rule.re.lastIndex = 0;
      for (const m of payload.text.matchAll(rule.re)) {
        findings.push({
          ruleId: `${rule.id}-encoded`,
          kind: "encoded",
          severity: rule.severity,
          layer: 3,
          label: `${rule.label}（编码载荷内）`,
          evidence: evidenceOf(payload.text, m.index ?? 0, m[0].length),
          offset: payload.offset,
        });
      }
    }
  }

  // ---- 第 3 层补强：部分编码的"解码后重扫" ----
  // 部分编码（百分号、UTF-16 原文字面量）只把**敏感词**藏起来，指令骨架仍留明文：
  //   "Please %69%67%6e%6f%72%65 all previous instructions"
  // 单独看解码出的 "ignore" 只有 6 字节，拼不出指令；必须把它放回句子里，
  // 整句变成 "Please ignore all previous instructions" 才是完整攻击。
  // 做法：对归一化文本做一次**保守的原地解码**（百分号 + UTF-16），
  // 再把结果与原文拼接成一个合成串喂给第 1 层——不改动 n，避免污染已采集的
  // 证据偏移量。
  const partiallyDecoded = decodePartially(n);
  if (partiallyDecoded !== n) {
    const combined = `${n}\n${partiallyDecoded}`;
    for (const rule of COMPILED_HIGH) {
      rule.re.lastIndex = 0;
      for (const m of combined.matchAll(rule.re)) {
        const inOriginal = m.index !== undefined && m.index < n.length;
        const ruleId = inOriginal ? `${rule.id}-encoded` : rule.id;
        // 原文侧已命中的不重复记（第 1 层会记一次）
        if (findings.some((f) => f.ruleId === ruleId)) continue;
        findings.push({
          ruleId,
          kind: "encoded",
          severity: rule.severity,
          layer: 3,
          label: `${rule.label}（编码载荷内）`,
          evidence: evidenceOf(combined, m.index ?? 0, m[0].length),
          offset: m.index ?? 0,
        });
      }
    }
  }

  // ---- 第 4 层：typo 模糊（默认关闭）----
  if (s.fuzzy === true) {
    findings.push(...detectFuzzy(n, s.fuzzyThreshold));
  }

  return {
    clean: findings.length === 0,
    findings,
    normalized: norm.changed,
    scannedBytes: bytes,
    truncated: truncated || decodeTruncated,
  };
}
