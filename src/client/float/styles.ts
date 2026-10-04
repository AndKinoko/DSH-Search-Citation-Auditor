/**
 * 悬浮窗子组件共享样式常量。
 */
import { MONO } from "../constants.js";

export const button: React.CSSProperties = {
  fontFamily: MONO,
  fontSize: 12,
  background: "none",
  border: "1px solid currentcolor",
  borderRadius: 3,
  color: "inherit",
  cursor: "pointer",
  padding: "1px 8px",
  marginRight: 6,
  marginTop: 2,
};

export const dimButton: React.CSSProperties = { ...button, color: "gray" };

export const link: React.CSSProperties = {
  background: "none",
  border: "none",
  color: "#4aa3ff",
  cursor: "pointer",
  font: "inherit",
  padding: 0,
  textDecoration: "underline",
};

export const dim: React.CSSProperties = { color: "gray" };

export function clamp(v: number, lo: number, hi: number): number {
  return Math.min(Math.max(v, lo), Math.max(lo, hi));
}

/**
 * `position: fixed` 元素用 right/bottom 定位时，可取值域。
 *
 * 关键：占位尺寸必须取**实际被拖的那个元素**的尺寸。悬浮球 44px、展开面板 380px，
 * 若两者共用一个按球算出来的值域，把球拖到左边缘后展开面板，左边缘会落到
 * `viewport - right - panelWidth` ≈ 负数——面板整个跑到视口外，而它唯一的拖拽条
 * 也在视口外，用户再也抓不回来。
 *
 * 视口比元素还窄时 hi 会小于 lo，clamp 内部再兜一次 Math.max(lo, hi)。
 */
export function fitBounds(viewport: number, size: number, margin: number): { lo: number; hi: number } {
  return { lo: margin, hi: Math.max(margin, viewport - size - margin) };
}
