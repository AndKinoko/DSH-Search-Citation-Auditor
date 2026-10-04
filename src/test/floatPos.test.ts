/**
 * 悬浮窗定位与拖拽回归测试。
 *
 * 用户报告的现象：展开后拖动条会跳出界面，随后界面卡住。
 * 根因是拖拽钳位按**悬浮球**（44px）算，而展开面板宽 380px —— 两者共用同一个
 * pos，把球拖到左边缘后展开，面板左边缘会落到视口之外，而面板唯一的拖拽条
 * （标题栏）也跟着跑到视口外，用户再也抓不回来；同时该坏位置会被持久化到
 * localStorage，下一次启动面板直接生在屏幕外。
 */
import assert from "node:assert/strict";
import test from "node:test";
import { clamp, fitBounds } from "../client/float/styles.js";
import { BALL_SIZE } from "../client/float/FloatBall.js";

const MARGIN = 12;
/** 与 FloatWindow.tsx 的常量保持一致（未导出，这里按同值断言其不变量）。 */
const PANEL_W = 380;
const PANEL_MAX_H = 0.6;

/** 元素左边缘：right 表示距右边的距离，故 left = 视口宽 - right - 宽度。 */
function leftEdge(viewportW: number, right: number, width: number): number {
  return viewportW - right - width;
}
function topEdge(viewportH: number, bottom: number, height: number): number {
  return viewportH - bottom - height;
}

test("悬浮球：拖到极限时仍在视口内", () => {
  const vw = 1280;
  const vh = 800;
  const rx = fitBounds(vw, BALL_SIZE, MARGIN);
  const ry = fitBounds(vh, BALL_SIZE, MARGIN);
  assert.ok(clamp(rx.hi, rx.lo, rx.hi) >= -0.0001, "球的左边缘不得为负");
  assert.ok(leftEdge(vw, rx.hi, BALL_SIZE) >= -0.0001, `球左边缘 ${leftEdge(vw, rx.hi, BALL_SIZE)} 越界`);
  assert.ok(topEdge(vh, ry.hi, BALL_SIZE) >= -0.0001, "球上边缘不得为负");
});

test("展开面板：按面板尺寸钳位后，任何取值都不会出视口（这正是修复点）", () => {
  for (const [vw, vh] of [
    [1280, 800],
    [1920, 1080],
    [1024, 768],
    [800, 600],
    [480, 900], // 窄屏
  ] as [number, number][]) {
    const panelH = vh * PANEL_MAX_H;
    const rx = fitBounds(vw, PANEL_W, MARGIN);
    const ry = fitBounds(vh, panelH, MARGIN);
    // 取值域两端都是边界情形，中间线性插值必然也在界内
    for (const right of [rx.lo, rx.hi, (rx.lo + rx.hi) / 2]) {
      assert.ok(
        leftEdge(vw, right, PANEL_W) >= -0.0001,
        `视口 ${vw}x${vh}: 面板左边缘 ${leftEdge(vw, right, PANEL_W)} 越界（right=${right}）`,
      );
    }
    for (const bottom of [ry.lo, ry.hi, (ry.lo + ry.hi) / 2]) {
      assert.ok(
        topEdge(vh, bottom, panelH) >= -0.0001,
        `视口 ${vw}x${vh}: 面板上边缘 ${topEdge(vh, bottom, panelH)} 越界（bottom=${bottom}）`,
      );
    }
  }
});

test("回归：若错用悬浮球尺寸给面板钳位，必然越界（说明这条测试确有区分度）", () => {
  const vw = 1280;
  const ballRx = fitBounds(vw, BALL_SIZE, MARGIN);
  // 旧代码就是这个值域：球能拖到最左，面板却比球宽得多
  const left = leftEdge(vw, ballRx.hi, PANEL_W);
  assert.ok(left < 0, `按球钳位时面板左边缘应为负，实际 ${left} —— 钳位尺寸必须换成面板的`);
});

test("视口比面板还窄时不产生非法值域", () => {
  const rx = fitBounds(200, PANEL_W, MARGIN);
  assert.ok(rx.hi >= rx.lo, "hi 不得小于 lo");
  assert.equal(clamp(-9999, rx.lo, rx.hi), rx.lo, "clamp 应收敛到合法区间");
});
