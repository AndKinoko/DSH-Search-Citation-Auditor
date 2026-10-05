/**
 * 悬浮球组件：可拖动的圆形按钮，显示盾牌图标和非可信域名数量角标。
 */
import React from "react";
import { LEVEL_COLOR } from "../constants.js";
import type { Level } from "../../auditor/types.js";
import type { FloatPos } from "./types.js";

export const BALL_SIZE = 44;

interface FloatBallProps {
  pos: FloatPos;
  nonTrusted: number;
  failed: boolean;
  hasVerdicts: boolean;
  onActivate: () => void;
  dragHandlers: {
    onPointerDown: (e: React.PointerEvent) => void;
    onPointerMove: (e: React.PointerEvent) => void;
    onPointerUp: (e: React.PointerEvent) => void;
    onPointerCancel: (e: React.PointerEvent) => void;
  };
}

export function FloatBall({ pos, nonTrusted, failed, hasVerdicts, onActivate, dragHandlers }: FloatBallProps): React.ReactElement {
  const activate = (): void => {
    // 键盘激活（Enter/空格）不是拖拽：直接视为点击，不触碰拖拽状态。
    onActivate();
  };
  const dotColor = failed
    ? "#e05555"
    : nonTrusted > 0
      ? LEVEL_COLOR.critical
      : hasVerdicts
        ? LEVEL_COLOR.trusted
        : "#888";
  const accessLabel =
    failed || nonTrusted > 0
      ? `引用来源威胁：${nonTrusted} 个非可信域名，按回车展开审查报告`
      : hasVerdicts
        ? "引用来源威胁：当前回复全部可信，按回车展开审查报告"
        : "引用来源威胁：按回车展开审查报告";

  return (
    <div
      data-citation-auditor-ball
      // 键盘与读屏用户的唯一入口：无它，整个悬浮窗功能对这部分用户不存在。
      // 保留 div 而不用 button，是避免把已经写死的圆形外观与拖拽热区一起拆开。
      role="button"
      tabIndex={0}
      aria-label={accessLabel}
      aria-expanded={false}
      onKeyDown={(e) => {
        if (e.key !== "Enter" && e.key !== " ") return;
        // 空格默认会滚动页面；这里是操作，不是翻页。
        e.preventDefault();
        e.stopPropagation();
        activate();
      }}
      onFocus={(e) => {
        e.currentTarget.style.outline = "2px solid #4aa3ff";
        e.currentTarget.style.outlineOffset = "2px";
      }}
      onBlur={(e) => {
        e.currentTarget.style.outline = "none";
      }}
      onPointerDown={dragHandlers.onPointerDown}
      onPointerMove={dragHandlers.onPointerMove}
      onPointerUp={dragHandlers.onPointerUp}
      onPointerCancel={dragHandlers.onPointerCancel}
      style={{
        position: "fixed",
        right: pos.right,
        bottom: pos.bottom,
        width: BALL_SIZE,
        height: BALL_SIZE,
        borderRadius: "50%",
        background: "var(--bg-color, #1e1e1e)",
        color: "var(--fg-color, #ddd)",
        border: `2px solid ${dotColor}`,
        boxShadow: "0 2px 10px rgba(0,0,0,0.35)",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        cursor: "grab",
        userSelect: "none",
        touchAction: "none",
        zIndex: 2147483000,
        fontSize: 20,
      }}
      title="引用来源威胁度（拖动移动，点击展开）"
    >
      <span aria-hidden="true">🛡</span>
      {nonTrusted > 0 ? (
        <span
          aria-hidden="true"
          style={{
            position: "absolute",
            top: -6,
            right: -6,
            minWidth: 18,
            height: 18,
            borderRadius: 9,
            background: dotColor,
            color: "#fff",
            fontSize: 11,
            lineHeight: "18px",
            textAlign: "center",
            padding: "0 4px",
          }}
        >
          {nonTrusted}
        </span>
      ) : null}
    </div>
  );
}
