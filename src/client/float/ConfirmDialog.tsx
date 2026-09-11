/**
 * 确认弹窗：模态对话框，显示标题、正文和按钮组。
 */
import React from "react";
import { MONO } from "../constants.js";
import type { ModalSpec } from "./types.js";
import { button, dim } from "./styles.js";

interface ConfirmDialogProps {
  modal: ModalSpec;
  onClose: () => void;
}

export function ConfirmDialog({ modal, onClose }: ConfirmDialogProps): React.ReactElement {
  return (
    <div
      role="dialog"
      aria-modal="true"
      style={{
        position: "fixed",
        inset: 0,
        background: "rgba(0,0,0,0.45)",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        zIndex: 9999,
      }}
      onClick={onClose}
    >
      <div
        style={{
          fontFamily: MONO,
          fontSize: 13,
          lineHeight: 1.7,
          border: "3px double currentcolor",
          borderRadius: 4,
          padding: "10px 14px",
          whiteSpace: "pre-wrap",
          background: "var(--bg-color, #1e1e1e)",
          color: "var(--fg-color, #ddd)",
          maxWidth: 460,
        }}
        onClick={(e) => e.stopPropagation()}
      >
        <div>{modal.title}</div>
        <div style={{ ...dim, margin: "6px 0" }}>{modal.body}</div>
        <div style={{ marginTop: 6 }}>
          {modal.buttons.map((b) => (
            <button key={b.label} type="button" style={button} onClick={b.onClick}>
              {b.label}
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}
