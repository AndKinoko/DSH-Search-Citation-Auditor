/**
 * 交互层回归测试（C-1 护栏）。
 *
 * 为什么单独建这个文件：此前 187 条测试全绿，却漏掉了「悬浮球被自己的 role
 * 排除、面板彻底打不开」这种阻断级缺陷——因为所有测试都只碰纯函数与端点，
 * **交互层（选择器策略 + 指针事件）零覆盖**。本文件把该层纳入测试网。
 *
 * 不引 jsdom：它不在 devDependencies，而这里要验的只是选择器匹配与父链查找
 * 策略，自带一个几十行的桩就够，且更少依赖。
 */
import assert from "node:assert/strict";
import test from "node:test";

/** 最小 DOM 桩：只满足 shouldSkipDrag 依赖的能力——closest() / contains()。 */
class El {
  tagName: string;
  attrs: Record<string, string>;
  children: El[];
  parent: El | null = null;
  constructor(tag: string, attrs: Record<string, string> = {}, children: El[] = []) {
    this.tagName = tag.toUpperCase();
    this.attrs = attrs;
    this.children = children;
    for (const c of children) c.parent = this;
  }
  matches(sel: string): boolean {
    const s = sel.trim();
    if (s.startsWith("[")) {
      const m = /^\[([^\]=]+)(?:=["']?([^\]"']+)["']?)?\]$/.exec(s);
      if (!m || m[1] === undefined) return false;
      const name = m[1];
      const val = m[2];
      if (!(name in this.attrs)) return false;
      return val === undefined ? true : String(this.attrs[name]) === val;
    }
    return this.tagName === s.toUpperCase();
  }
  closest(sel: string): El | null {
    let cur: El | null = this;
    while (cur) {
      if (sel.split(",").some((one) => cur!.matches(one))) return cur;
      cur = cur.parent;
    }
    return null;
  }
  contains(other: El): boolean {
    let cur: El | null = other;
    while (cur) {
      if (cur === this) return true;
      cur = cur.parent;
    }
    return false;
  }
}

// 全局 Element：让 `target instanceof Element` 成立
(globalThis as { Element?: unknown }).Element = El;

// 动态导入：必须在 Element 定义之后（模块求值时会用到它）
const { shouldSkipDrag } = await import("../client/FloatWindow.js");

/** 桩元素 → DOM 类型的单向断言：这里只测选择器策略，不测 DOM 本体。 */
const asTarget = (e: El): EventTarget => e as unknown as EventTarget;
const asElement = (e: El): Element => e as unknown as Element;

// ---- 悬浮球 DOM：带 role="button"（M9-d 为键盘可达性加入）----
function ball(): { root: El; icon: El; badge: El } {
  const root = new El("div", { "data-citation-auditor-ball": "", role: "button" });
  const icon = new El("span", { "aria-hidden": "true" });
  const badge = new El("span", { "aria-hidden": "true" });
  icon.parent = root;
  badge.parent = root;
  return { root, icon, badge };
}

// ---- 面板 DOM：标题栏/正文（非交互，可拖）+ 操作控件（不可拖）----
function panel(): { root: El; header: El; text: El; btn: El; input: El; inner: El } {
  const root = new El("div", { "data-citation-auditor-panel": "" });
  const header = new El("div");
  const text = new El("span");
  const btn = new El("button");
  const input = new El("input");
  const inner = new El("span");
  for (const c of [header, text, btn, input]) c.parent = root;
  inner.parent = btn;
  return { root, header, text, btn, input, inner };
}

test("C-1 回归：悬浮球带 role=button 时仍能接收指针（否则面板打不开）", () => {
  // 阻断级缺陷的护栏：该球为键盘可达性加了 role="button"，而 role 命中
  // NO_DRAG_SELECTOR，球于是把自己的指针事件全挡掉；aria-hidden 不影响
  // closest()，图标 span 同样被挡。表现：点击与拖拽双双失效。
  const { root, icon, badge } = ball();
  for (const [name, target] of [["球自身", root], ["图标", icon], ["角标", badge]] as const) {
    assert.equal(
      shouldSkipDrag(asTarget(target), asElement(root)),
      false,
      `${name} 落在悬浮球热区内必须放行`,
    );
  }
});

test("面板：标题栏与非交互文字区仍可拖（用户最自然的拖拽位置）", () => {
  const { root, header, text } = panel();
  assert.equal(shouldSkipDrag(asTarget(header), asElement(root)), false, "标题栏必须能拖");
  assert.equal(shouldSkipDrag(asTarget(text), asElement(root)), false, "正文非交互区必须能拖");
});

test("面板：操作控件不可拖（点它们要执行动作而不是挪窗口）", () => {
  const { root, btn, input } = panel();
  assert.equal(shouldSkipDrag(asTarget(btn), asElement(root)), true, "按钮必须排除");
  assert.equal(shouldSkipDrag(asTarget(input), asElement(root)), true, "输入框必须排除");
});

test("面板：按钮的子元素同样排除（closest 沿父链向上查）", () => {
  const { root, inner } = panel();
  assert.equal(shouldSkipDrag(asTarget(inner), asElement(root)), true, "按钮内文字不该触发拖拽");
});

test("边界：非 Element 目标与不在子树内的目标一律放行", () => {
  const { root } = panel();
  assert.equal(shouldSkipDrag(null, asElement(root)), false, "null 不该抛也不该拦");
  assert.equal(shouldSkipDrag("s" as unknown as EventTarget, asElement(root)), false, "非 Element 放行");
  const outside = new El("button");
  assert.equal(shouldSkipDrag(asTarget(outside), asElement(root)), false, "不在子树内不属本次热区");
});

test("热区豁免不外溢：其它 role=button 元素仍被排除", () => {
  // 豁免必须精确到 [data-citation-auditor-ball]。若写成「所有 role 都放行」，
  // 面板里的按钮又开始拖窗——等于把原问题换个方向复现。
  const root = new El("div");
  const other = new El("div", { role: "button" });
  other.parent = root;
  assert.equal(shouldSkipDrag(asTarget(other), asElement(root)), true, "非悬浮球的 role=button 仍应排除");
});