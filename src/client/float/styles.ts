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
