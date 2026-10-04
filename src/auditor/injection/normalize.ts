/**
 * 归一化：检测的前置条件，也是第一道防线。
 *
 * 不归一化，patterns.ts 的每一条正则都能被零宽字符轻松绕过。归一化做四件事：
 *  1. 剔除不可见/零宽字符（U+200B-200D、U+FEFF、U+00AD 等）
 *  2. 解 HTML 实体（&#x69; / &#105; / &lt; 等十进制与十六进制形式）
 *  3. 全角转半角（U+FF01-FF5E → U+0021-007E）
 *  4. 折叠空白、压缩连续重复字符（OWASP 的 (.)\1{3,}）
 *
 * 关键设计：归一化本身就是信号。即使没有任何规则命中，「页面里凭空含零宽
 * 字符 / HTML 实体」也值得记一条 structural 发现——真实正文不会长这样。
 * 所以这里返回的 stats 不是副产品，是 detect.ts 的输入之一。
 *
 * 不可见字符的码点以 \u 转义书写：这些字符本身在源码里不可见，直接写字面量
 * 会让「这行到底匹配了哪些码点」变得不可读，也容易被编辑器/工具悄悄改写。
 * INVISIBLE_RE 由 INVISIBLE_CODE_POINTS 构造（而非另写一个字符类），
 * 保证「正则匹配的集合」与「逐字统计的集合」永不漂移。
 *
 * 纯函数、同步、零 IO。
 */

/**
 * 不可见字符码点：零宽字符、双向覆写控制符、组合连接符、填充字符。
 * 不含空白类字符（见 SPACE_LIKE_CODE_POINTS）——那些是合法排版字符。
 * 既是正则匹配的来源，也是逐字统计与「夹在单词内」判定的依据。
 */
const INVISIBLE_CODE_POINTS = new Set<number>([
  0x00ad, // SOFT HYPHEN
  0x034f, // COMBINING GRAPHEME JOINER
  0x061c, // ARABIC LETTER MARK
  0x115f, // HANGUL CHOSEONG FILLER
  0x1160, // HANGUL JUNGSEONG FILLER
  0x17b4, // KHMER VOWEL INHERENT AQ
  0x17b5, // KHMER VOWEL INHERENT AA
  0x180e, // MONGOLIAN VOWEL SEPARATOR
  0x200b, // ZERO WIDTH SPACE
  0x200c, // ZERO WIDTH NON-JOINER
  0x200d, // ZERO WIDTH JOINER
  0x200e, // LEFT-TO-RIGHT MARK
  0x200f, // RIGHT-TO-LEFT MARK
  0x202a, // LRE
  0x202b, // RLE
  0x202c, // PDF
  0x202d, // LRO
  0x202e, // RLO
  0x2060, // WORD JOINER
  0x2061, // FUNCTION APPLICATION
  0x2062, // INVISIBLE TIMES
  0x2063, // INVISIBLE SEPARATOR
  0x2064, // INVISIBLE PLUS
  0x3164, // HANGUL FILLER
  0xfeff, // ZERO WIDTH NO-BREAK SPACE / BOM
  0xffa0, // HALFWIDTH HANGUL FILLER
]);

/**
 * 空白类「看不见但合法」的字符：半角/全角不换行空格、各种间距。
 *
 * 与 INVISIBLE_CODE_POINTS 严格分开——它们在中文排版和网页里是常规字符，
 * 把它们当成攻击信号会让全角正文（乃至普通中文页面）持续误报。
 * 归一化阶段照常把它们折叠成普通空格（toHalfWidth + 空白折叠已覆盖）。
 */
const SPACE_LIKE_CODE_POINTS = new Set<number>([
  0x00a0, // NO-BREAK SPACE
  0x2007, // FIGURE SPACE
  0x2008, // PUNCTUATION SPACE
  0x2009, // THIN SPACE
  0x200a, // HAIR SPACE
  0x202f, // NARROW NO-BREAK SPACE
  0x205f, // MEDIUM MATHEMATICAL SPACE
  0xfeff, // BOM 常见于 UTF-8 中间：算不可见，但此处不重复登记
]);

/** 空白折叠用的字符类：常规空白 + SPACE_LIKE（由集合构造，避免两处定义漂移）。 */
const SPACE_FOLD_RE = new RegExp(
  `[\\s${Array.from(SPACE_LIKE_CODE_POINTS, (cp) => `\\u${cp.toString(16).padStart(4, "0")}`).join("")}]+`,
  "gu",
);

/** 由码点集合构造匹配正则：唯一真源在 INVISIBLE_CODE_POINTS。 */
const INVISIBLE_RE = new RegExp(
  `[${Array.from(INVISIBLE_CODE_POINTS, (cp) => `\\u${cp.toString(16).padStart(4, "0")}`).join("")}]`,
  "gu",
);

/** 常见同形异义字符 → 拉丁字母（Cyrillic / Greek 混入）。默认不折叠，见 normalize 的 opts。 */
const HOMOGLYPHS: Record<string, string> = {
  а: "a", е: "e", о: "o", р: "p", с: "c",
  х: "x", у: "y", і: "i", ј: "j",
  ѕ: "s", ԁ: "d", һ: "h", ɡ: "g",
  ν: "v", ρ: "p", τ: "t",
  Α: "A", Β: "B", Ε: "E", Ζ: "Z", Η: "H",
  Ι: "I", Κ: "K", Μ: "M", Ν: "N", Ο: "O", Ρ: "P", Τ: "T", Υ: "Y", Χ: "X",
};

export interface NormalizeResult {
  /** 归一化后的文本，供正则检测使用（已折叠重复字符与空白）。 */
  text: string;
  /**
   * 只做了「不可见字符剔除 + 实体解码 + 全角转半角」的文本，
   * **未**折叠重复字符与空白。专供编码载荷提取（detect.ts 第 3 层）使用。
   *
   * 为什么需要这一份：重复折叠会把 `AAAA...`（200k）压成 `A`，
   * Base64 候选因此在提取前就被摧毁，长度判断与候选数上限全部失真。
   */
  textForDecode: string;
  /** 原文是否含不可见字符。 */
  hadInvisible: boolean;
  /** 原文是否含「疑似藏字」的 HTML 实体（排版实体如 &nbsp; 不计）。 */
  hadSuspiciousEntities: boolean;
  /** 疑似藏字的实体出现次数。 */
  suspiciousEntityCount: number;
  /** 不可见字符个数。 */
  invisibleCount: number;
  /** 不可见字符占长度比。 */
  invisibleRatio: number;
  /** 原文含连续重复字符（>=4）的段落数。 */
  repeatRuns: number;
  /** 归一化是否改变了文本（任何一项都算）。 */
  changed: boolean;
}

const ENTITY_RE = /&(#[xX][0-9a-fA-F]+|#\d+|[a-zA-Z][a-zA-Z0-9]{1,9});/g;
const REPEAT_RE = /(.)\1{3,}/gu;
/** 空白折叠：SPACE_FOLD_RE（常规空白 + 各类不换行/全角空格）。 */
const WHITESPACE_RE = SPACE_FOLD_RE;
const FULLWIDTH_RE = /[！-～]/gu;

/** 常见命名 HTML 实体。数值实体在 decodeEntities 里直接按码点算。 */
const NAMED_ENTITIES: Record<string, string> = {
  lt: "<", gt: ">", quot: '"', apos: "'", amp: "&", nbsp: " ",
  colon: ":", semi: ";", num: "#", dollar: "$", percnt: "%",
  lpar: "(", rpar: ")", ast: "*", plus: "+", equals: "=",
  quest: "?", commat: "@", excl: "!", period: ".", sol: "/", bsol: "\\",
  verbar: "|", comma: ",", lsqb: "[", rsqb: "]", lbrack: "[", rbrack: "]",
  lcub: "{", rcub: "}", lowbar: "_", grave: "`", tilde: "~",
  hat: "^", middot: "·",
  aacute: "a", eacute: "e", iacute: "i", oacute: "o", uacute: "u", ntilde: "n",
};

/**
 * 「排版实体」白名单：这些命名实体的唯一用途是排版，不是藏字。
 *
 * 没有它，`&nbsp;` / `&amp;` 会让每一个真实网页都产出一条注入告警——
 * 误报到那一步，用户会开始无视所有告警，整套检测就废了。
 */
const TYPOGRAPHIC_ENTITIES = new Set([
  "nbsp", "amp", "lt", "gt", "quot", "apos", "middot", "hellip", "mdash", "ndash",
  "copy", "reg", "trade", "deg", "plusmn", "times", "divide", "frac12", "laquo",
  "raquo", "sect", "para", "middot", "bull", "dagger", "euro", "pound", "yen",
  "cent", "sup2", "sup3", "frac14", "frac34", "ne", "le", "ge", "minus", "plus",
  "lsquo", "rsquo", "ldquo", "rdquo", "sbquo", "bdquo", "lsaquo", "rsaquo", "oline",
  "frasl", "spades", "clubs", "hearts", "diams", "permil", "prime", "Prime",
]);

/**
 * 解码 HTML 实体。
 *
 * suspiciousCount 单独统计「疑似藏字」的实体：数值实体（`&#x69;`）与不在
 * TYPOGRAPHIC_ENTITIES 里的命名实体。`&nbsp;` 这类排版实体照常解码但不计数——
 * 它们在真实页面里遍布，算告警等于对每个网页都误报一次。
 */
function decodeEntities(input: string): { text: string; suspiciousCount: number } {
  let suspiciousCount = 0;
  const text = input.replace(ENTITY_RE, (match, body: string) => {
    const lower = body.toLowerCase();
    const isNumeric = lower.startsWith("#");
    let decoded: string | null = null;
    if (lower.startsWith("#x")) {
      const code = Number.parseInt(lower.slice(2), 16);
      if (Number.isFinite(code) && code >= 0x20 && code <= 0x7e) decoded = String.fromCharCode(code);
    } else if (isNumeric) {
      const code = Number.parseInt(lower.slice(1), 10);
      if (Number.isFinite(code) && code >= 0x20 && code <= 0x7e) decoded = String.fromCharCode(code);
    } else {
      decoded = NAMED_ENTITIES[lower] ?? null;
    }
    if (decoded === null) return match; // 未知实体原样保留，避免误伤正文
    // 数值实体一律可疑（排版不需要 &#105;）；命名实体按白名单判定
    if (isNumeric || !TYPOGRAPHIC_ENTITIES.has(lower)) suspiciousCount += 1;
    return decoded;
  });
  return { text, suspiciousCount };
}

/** 全角 ASCII 与全角空格转半角。 */
function toHalfWidth(input: string): string {
  return input.replace(FULLWIDTH_RE, (ch) => String.fromCharCode(ch.charCodeAt(0) - 0xfee0));
}

/**
 * 主归一化入口。
 * @param raw 原始文本（如 web_fetch 的 TextBlock 内容）。
 * @param opts.homoglyphs 折叠同形异义字符。默认 false：会提高误报，需用户显式开启。
 * @returns 归一化结果与统计信号。
 */
export function normalize(raw: string, opts: { homoglyphs?: boolean } = {}): NormalizeResult {
  // 不可见字符统计必须在「剔除之前」算，剔除后就无从判断原文是否含藏字。
  let invisibleCount = 0;
  for (const ch of raw) {
    const cp = ch.codePointAt(0);
    if (cp !== undefined && INVISIBLE_CODE_POINTS.has(cp)) invisibleCount += 1;
  }
  const repeatRuns = (raw.match(REPEAT_RE) ?? []).length;

  let text = raw.replace(INVISIBLE_RE, "");
  const decoded = decodeEntities(text);
  text = decoded.text;
  text = toHalfWidth(text);

  if (opts.homoglyphs === true) {
    text = text.replace(/[^\x00-\x7f]/gu, (ch) => HOMOGLYPHS[ch] ?? ch);
  }

  // 载荷提取用的副本：到此为止，不再折叠（见 textForDecode 的注释）
  const textForDecode = text;

  // 压缩重复字符放在实体解码之后：否则被编码藏起来的 payload 会被这一步拆散。
  text = text.replace(REPEAT_RE, "$1");
  // 折叠空白放最后：前面各步可能产生新的空白
  text = text.replace(WHITESPACE_RE, " ").trim();

  return {
    text,
    textForDecode,
    hadInvisible: invisibleCount > 0,
    hadSuspiciousEntities: decoded.suspiciousCount > 0,
    suspiciousEntityCount: decoded.suspiciousCount,
    invisibleCount,
    invisibleRatio: raw.length > 0 ? invisibleCount / raw.length : 0,
    repeatRuns,
    changed: text !== raw,
  };
}

/** 某码点是否为不可见字符（detect.ts 用它判断「藏字是否夹在单词内部」）。 */
export function isInvisibleCodePoint(cp: number): boolean {
  return INVISIBLE_CODE_POINTS.has(cp);
}

/**
 * 不可见字符是否夹在两个字母/数字之间。
 *
 * 比「页面含零宽字符」严重得多：整页散布零宽空格可能是排版产物，但把零宽字符
 * 精确塞进单词内部（ig<U+200B>nore）只有定向藏字才会这么干。字符判定复用
 * INVISIBLE_CODE_POINTS，不另写字面量。
 */
export function hasInvisibleInsideWord(text: string): boolean {
  const chars = Array.from(text);
  for (let i = 1; i < chars.length - 1; i++) {
    const cp = chars[i]!.codePointAt(0);
    if (cp === undefined || !INVISIBLE_CODE_POINTS.has(cp)) continue;
    const prev = chars[i - 1]!;
    const next = chars[i + 1]!;
    const isWordChar = (ch: string): boolean => /\p{L}|\p{N}/u.test(ch);
    if (isWordChar(prev) && isWordChar(next)) return true;
  }
  return false;
}

/** 某字符是否为可折叠的同形异义字符（归一化开启 homoglyphs 时才处理）。 */
export function isHomoglyph(ch: string): boolean {
  return Object.hasOwn(HOMOGLYPHS, ch);
}
