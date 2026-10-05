/**
 * 会话选择回归测试。
 *
 * 用户反馈的现象：浮窗没有跟随「当前打开的对话」，报告要么不出现，要么是上一段
 * 对话的结论。根因有三条：
 *
 *  1. 旧实现取 `list.ids[0]`。0.2.0 的 SessionListState 是
 *     { ids, byId, phase, projectionsBySession }，**没有 current**，导航归视图属主
 *     所有；ids 是宿主列表顺序（通常最近在前），与当前打开的是哪个会话无关。
 *     —— 这一条由 pickCurrentSession 覆盖，下面有测试。
 *  2. 即便选对了会话，不自己 retain 就拿不到 binding（ISessions.binding 只「借用
 *     已 retain 的 generation」，没有则返回 undefined），于是 chatTarget 永远
 *     undefined，浮窗一直停在「等最近一次回复定稿后自动分析」。
 *     —— 这一条在 useRetainedSession 里，是带副作用的 hook，纯函数层覆盖不了，
 *        只能靠类型检查 + 实机验证。
 *  3. **自己持有的会话参与了自己的投票**。useRetainedSession 用
 *     source:"citationAuditorFloat" 持有选中的会话，下一次 list 快照里这个会话的
 *     retainedBy 必然非空，于是「选 A→持有 A→A 有计数→继续选 A」形成正反馈，
 *     切会话后面板仍在显示旧结论。2026-10-06 实机确认。
 *     —— 由 pickCurrentSession 的 excludeSource 参数消除，下面有测试。
 */
import assert from "node:assert/strict";
import test from "node:test";
import { pickCurrentSession } from "../client/FloatWindow.js";
import type { SessionId } from "@deepseek-ai/dsh-client-connection/client";

/** SessionId 是品牌类型，测试里用普通字符串代表。 */
/** 浮窗自己的 retain source（与 FloatWindow.tsx 的 CITE_SOURCE 一致）。 */
const SELF = "citationAuditorFloat";

const id = (s: string): SessionId => s as unknown as SessionId;

test("没有任何会话被 retain 时退回列表首位（至少不空白）", () => {
  assert.equal(pickCurrentSession({ ids: [id("s1"), id("s2")], byId: {} }), "s1");
});

test("scopeId 优先：宿主作用域标签最权威", () => {
  // scopeId 是插件挂载点所在的会话。即使别的会话也有 retain 计数，
  // 作用域标签也应当胜出——它来自宿主自己挂的 scope tag，不是猜的。
  const list = {
    ids: [id("s1"), id("s2")],
    byId: { [id("s1")]: { retainedBy: { viewer: 1 } }, [id("s2")]: { retainedBy: { viewer: 1 } } },
  };
  assert.equal(pickCurrentSession(list, { scopeId: id("s2") }), "s2", "scopeId 必须胜出");
  // scopeId 必须仍是列表成员，防止脏 id 把面板导向不存在的会话
  assert.equal(pickCurrentSession(list, { scopeId: id("sx") }), "s1", "列表外的 scopeId 不得采用");
});

test("旧宿主若仍带 current，优先用它", () => {
  const list = {
    current: id("s2"),
    ids: [id("s1"), id("s2")],
    byId: { [id("s1")]: { retainedBy: { someViewer: 1 } }, [id("s2")]: { retainedBy: {} } },
  };
  assert.equal(pickCurrentSession(list), "s2", "有 current 时不应被 retainedBy 覆盖");
});

test("只监控被 retain 的那个会话，而不是 ids[0]", () => {
  const list = {
    ids: [id("s1"), id("s2")],
    byId: { [id("s1")]: { retainedBy: {} }, [id("s2")]: { retainedBy: { dshClientUiChat: 1 } } },
  };
  assert.equal(pickCurrentSession(list), "s2", "必须跟随被 retain 的会话");
});

test("retainedBy 计数为 0 的会话不算被打开", () => {
  const list = {
    ids: [id("s1"), id("s2")],
    byId: { [id("s1")]: { retainedBy: { viewer: 0 } }, [id("s2")]: { retainedBy: { viewer: 1 } } },
  };
  assert.equal(pickCurrentSession(list), "s2");
});

test("多个会话被 retain 时取列表顺序最靠前者（通常是最近打开的）", () => {
  const list = {
    ids: [id("s1"), id("s2"), id("s3")],
    byId: {
      [id("s1")]: { retainedBy: { a: 1 } },
      [id("s2")]: { retainedBy: { b: 1 } },
      [id("s3")]: { retainedBy: { c: 1 } },
    },
  };
  assert.equal(pickCurrentSession(list), "s1");
});

test("自己持有的会话不算票（反正反馈自锁）", () => {
  // 场景复现：浮窗先选了 A 并持有（source:SELF），用户随后切到 B。
  // B 被宿主视图 retain，A 只剩浮窗自己那份。若自己的持有算票，
  // A 和 B 都有计数，“取列表首位”就可能继续选 A——切会话等于没切。
  const ids = [id("sA"), id("sB")];
  const stuck = pickCurrentSession(
    { ids, byId: { [id("sA")]: { retainedBy: { [SELF]: 1 } }, [id("sB")]: { retainedBy: { chatView: 1 } } } },
    { excludeSource: SELF },
  );
  assert.equal(stuck, "sB", "只剩自己持有的旧会话不得再被选中");
  // 两个都只有自己持有 → 都不算票 → 退回列表首位，而不是粘住旧的
  const bothSelf = pickCurrentSession(
    { ids, byId: { [id("sA")]: { retainedBy: { [SELF]: 1 } }, [id("sB")]: { retainedBy: { [SELF]: 1 } } } },
    { excludeSource: SELF },
  );
  assert.equal(bothSelf, "sA", "无人真正打开时退回首位");
});

test("容错：空快照 / 缺字段 / 非数组 ids", () => {
  assert.equal(pickCurrentSession(undefined), undefined);
  assert.equal(pickCurrentSession({}), undefined);
  assert.equal(pickCurrentSession({ ids: [] }), undefined);
  assert.equal(pickCurrentSession({ ids: [id("s1")] }), "s1", "没有 byId 时退回首位");
  assert.equal(
    pickCurrentSession({ ids: [id("s1")], byId: { [id("s1")]: { retainedBy: undefined } } }),
    "s1",
    "retainedBy 为 undefined 视为未 retain",
  );
});

test("会话切换：选中的会话随 retain 转移而改变", () => {
  const ids = [id("s1"), id("s2")];
  assert.equal(
    pickCurrentSession({ ids, byId: { [id("s1")]: { retainedBy: { v: 1 } }, [id("s2")]: {} } }),
    "s1",
    "打开 s1",
  );
  assert.equal(
    pickCurrentSession({ ids, byId: { [id("s1")]: {}, [id("s2")]: { retainedBy: { v: 1 } } } }),
    "s2",
    "切到 s2 后必须跟随",
  );
});