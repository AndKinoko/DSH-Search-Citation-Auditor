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
  dragHandlers: {
    onPointerDown: (e: React.PointerEvent) => void;
    onPointerMove: (e: React.PointerEvent) => void;
    onPointerUp: (e: React.PointerEvent) => void;
    onPointerCancel: (e: React.PointerEvent) => void;
  };
}

export function FloatBall({ pos, nonTrusted, failed, hasVerdicts, dragHandlers }: FloatBallProps): React.ReactElement {
  const dotColor = failed
    ? "#e05555"
    : nonTrusted > 0
      ? LEVEL_COLOR.critical
      : hasVerdicts
        ? LEVEL_COLOR.trusted
        : "#888";

  return (
    <div
      data-citation-auditor-ball
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
      🛡
      {nonTrusted > 0 ? (
        <span
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
