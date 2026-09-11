/**
 * 审计列表面板：显示域名威胁评分和操作按钮。
 */
import React from "react";
import { LEVEL_LABEL, ENFORCEMENT_LABEL } from "../../auditor/types.js";
import { LEVEL_COLOR } from "../constants.js";
import type { AuditVerdict } from "./types.js";
import { button, dimButton, link, dim } from "./styles.js";

interface AuditPanelProps {
  analyzing: boolean;
  failed: boolean;
  auditEnabled: boolean | undefined;
  verdicts: AuditVerdict[];
  ignored: ReadonlySet<string>;
  busy: boolean;
  onAddBlocklist: (v: AuditVerdict) => void;
  onConfirmRemove: (what: string, domain: string, op: "unblock" | "unwhitelist") => void;
  onAddWhitelist: (domain: string) => void;
  onIgnore: (domain: string) => void;
  onOpenDomain: (domain: string) => void;
}

export function AuditPanel({
  analyzing,
  failed,
  auditEnabled,
  verdicts,
  ignored,
  busy,
  onAddBlocklist,
  onConfirmRemove,
  onAddWhitelist,
  onIgnore,
  onOpenDomain,
}: AuditPanelProps): React.ReactElement {
  const shown = verdicts.filter((v) => !ignored.has(v.domain));

  return (
    <div style={{ overflowY: "auto", padding: "8px 10px", lineHeight: 1.6 }}>
      {analyzing ? <div style={{ color: "gray" }}>⏳ 分析最近回复中…</div> : null}
      {!analyzing && failed ? (
        <div style={{ color: "#e05555" }}>数据端点不可达（host 端点未就绪或已停用）。</div>
      ) : null}
      {!analyzing && !failed && auditEnabled !== undefined && !auditEnabled ? (
        <div style={{ color: "gray" }}>插件已休眠（⚙ 设置里可重新开启）。</div>
      ) : null}
      {!analyzing && !failed && auditEnabled !== undefined && auditEnabled && shown.length === 0 ? (
        <div style={{ color: "gray" }}>（最近回复里没有网址，或全部已忽略）</div>
      ) : null}
      {!analyzing && !failed && auditEnabled === undefined ? (
        <div style={{ color: "gray" }}>等最近一次回复定稿后自动分析。</div>
      ) : null}
      {shown.map((v) => (
        <div key={v.domain} style={{ margin: "4px 0" }}>
          <div>
            <span style={{ color: LEVEL_COLOR[v.level] }}>{LEVEL_LABEL[v.level]}</span>
            {` ${v.score}分  `}
            <button type="button" style={link} title="新标签打开" onClick={() => onOpenDomain(v.domain)}>
              {v.domain}
            </button>
          </div>
          {v.reasons.length > 0 || v.creationDate !== undefined || v.inBlocklist ? (
            <div style={{ paddingLeft: "1.2em", color: "gray", fontSize: 12 }}>
              {v.reasons.length > 0 ? `原因: ${v.reasons.join(" + ")}` : ""}
              {v.creationDate !== undefined ? `（创建于 ${v.creationDate.slice(0, 10)}）` : ""}
              {v.inBlocklist && v.action !== undefined && v.action !== "allow"
                ? `［命中拦截名单：${ENFORCEMENT_LABEL[v.action]}］`
                : ""}
            </div>
          ) : null}
          {v.level !== "trusted" ? (
            <div style={{ paddingLeft: "1.2em" }}>
              {v.inBlocklist ? (
                <button
                  type="button"
                  style={dimButton}
                  disabled={busy}
                  onClick={() => onConfirmRemove("拦截名单", v.domain, "unblock")}
                >
                  ✓ 已拦截
                </button>
              ) : (
                <button type="button" style={button} disabled={busy} onClick={() => onAddBlocklist(v)}>
                  ➕ 加入拦截名单
                </button>
              )}
              {v.inWhitelist ? (
                <button
                  type="button"
                  style={dimButton}
                  disabled={busy}
                  onClick={() => onConfirmRemove("白名单", v.domain, "unwhitelist")}
                >
                  ✓ 已白名单
                </button>
              ) : (
                <button
                  type="button"
                  style={button}
                  disabled={busy}
                  onClick={() => onAddWhitelist(v.domain)}
                >
                  ➕ 加入白名单
                </button>
              )}
              <button
                type="button"
                style={dimButton}
                onClick={() => onIgnore(v.domain)}
              >
                忽略
              </button>
            </div>
          ) : null}
        </div>
      ))}
      {verdicts.length > 0 ? (
        <div style={{ marginTop: 6, color: "gray", fontSize: 11 }}>
          分数与 citation_audit 工具一致；名单写入立即生效。
        </div>
      ) : null}
    </div>
  );
}
