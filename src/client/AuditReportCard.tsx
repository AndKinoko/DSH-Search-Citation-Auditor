/**
 * citation_audit 的交互报表行（Phase 3）：注册进 keyed slot
 * tool.call.toolview（key = "citation_audit"），在会话里替换通用工具卡片。
 *
 * 数据流：通用卡片只能拿到 render 出的纯文本报表，拿不到结构化 verdicts，
 * 所以这里用工具入参里的 text 重跑一次 host 的 /api/citation-auditor/audit
 * （年龄走缓存，成本可忽略），同时拿到按钮状态机需要的当前设置事实
 * （mode / blocklistEnabled）与名单隶属（inWhitelist / inBlocklist）。
 * 按钮写入走 /api/citation-auditor/list，与 citation_manage 同一底层。
 *
 * 按钮状态机（IDE-prompt-主任务-v0.3 Phase 3）：
 *  - [➕ 加入拦截名单]：当前模式 blocklistEnabled 开 → 写入，变灰"✓ 已拦截"；
 *    再点弹确认后移除。关 → 弹窗（开启并保存 / 仅保存（本会话不再提示）/ 取消）
 *  - [➕ 加入白名单]：写入变灰"✓ 已白名单"；再点弹确认后移除
 *  - [忽略]：本次展示内隐藏该域名（仅 UI 层）
 *  - 点域名 → 新标签打开 https://<domain>
 *
 * 关于"去设置页开启"的偏差：dsh 设置壳的打开状态是组件内部 state，没有跨插件
 * 的编程式打开 API；弹窗首按钮改为"开启并保存"——经插件自有 /settings 端点
 * 直接置位该模式的拦截名单开关并落盘 settings.json（settings 服务命名空间在
 * 当前宿主环境不可靠，实测 settings-not-exposed），效果等价且少一跳。
 */
import { useCallback, useEffect, useState } from "react";
import type { ToolCallViewProps } from "@deepseek-ai/dsh-client-ui-tool/client";
import type { CitationSettingsSection } from "../settingsSection.js";
import { LEVEL_LABEL, type Level } from "../auditor/types.js";

/** 组件经注册 inject 拿到的脸（设置/名单读写走插件自有 /api 端点，无需注入）。 */
export interface AuditRowInject {}

type AuditRowProps = ToolCallViewProps & AuditRowInject;

/** GET /api/citation-auditor/audit 负载里的单条判决。 */
interface AuditVerdict {
  domain: string;
  score: number;
  level: Level;
  reasons: string[];
  sourceKind: string;
  creationDate?: string;
  inWhitelist: boolean;
  inBlocklist: boolean;
}

/** GET /api/citation-auditor/audit 的负载。 */
interface AuditData {
  ok: boolean;
  enabled: boolean;
  mode: CitationSettingsSection["mode"];
  blocklistEnabled: boolean;
  summary: string;
  verdicts: AuditVerdict[];
}

/** 弹窗描述：标题 + 正文 + 按钮组。 */
interface ModalSpec {
  title: string;
  body: string;
  buttons: { label: string; onClick: () => void }[];
}

const MONO = "ui-monospace, SFMono-Regular, Consolas, 'Courier New', monospace";

const box: React.CSSProperties = {
  fontFamily: MONO,
  fontSize: 13,
  lineHeight: 1.7,
  border: "3px double currentcolor",
  borderRadius: 4,
  padding: "10px 14px",
  whiteSpace: "pre-wrap",
};

const button: React.CSSProperties = {
  fontFamily: MONO,
  fontSize: 12,
  background: "none",
  border: "1px solid currentcolor",
  borderRadius: 3,
  color: "inherit",
  cursor: "pointer",
  padding: "1px 8px",
  marginRight: 6,
};

const dimButton: React.CSSProperties = { ...button, color: "gray" };

const link: React.CSSProperties = {
  background: "none",
  border: "none",
  color: "#4aa3ff",
  cursor: "pointer",
  font: "inherit",
  padding: 0,
  textDecoration: "underline",
};

const dim: React.CSSProperties = { color: "gray" };

const LEVEL_COLOR: Record<Level, string> = {
  trusted: "#58a65c",
  suspicious: "#d98a2b",
  warning: "#d9a036",
  critical: "#e05555",
};

/** 模式 → 设置文档里对应"该模式拦截名单开关"的字段名。 */
const BLOCKLIST_FIELD: Record<CitationSettingsSection["mode"], keyof CitationSettingsSection> = {
  whitelist: "blocklistEnabledWhitelist",
  normal: "blocklistEnabledNormal",
  simple: "blocklistEnabledSimple",
};

const MODE_LABEL: Record<CitationSettingsSection["mode"], string> = {
  whitelist: "白名单模式",
  normal: "普通模式",
  simple: "简单模式",
};

/** 从工具入参还原审计文本；解析失败返回 undefined（退化为纯报表展示）。 */
function textFromBlock(block: AuditRowProps["block"]): string | undefined {
  const settled = "kind" in block;
  const argsRaw = (settled ? block.call?.argsRaw : block.argsRaw) ?? "";
  try {
    const parsed = JSON.parse(argsRaw) as unknown;
    if (typeof parsed === "object" && parsed !== null && typeof (parsed as Record<string, unknown>).text === "string") {
      return (parsed as Record<string, unknown>).text as string;
    }
  } catch {
    // 流式阶段可能是截断的 JSON；等 settled 后重试
  }
  return undefined;
}

/** 已落盘的纯文本报表（block.content 的 text 块），兜底与"原始报表"展开用。 */
function reportTextFromBlock(block: AuditRowProps["block"]): string | null {
  if (!("kind" in block)) return null;
  const parts: string[] = [];
  for (const item of block.content) {
    if (item.type === "text") parts.push(item.text);
  }
  return parts.join("\n") || null;
}

export function CitationAuditRow(props: AuditRowProps): React.ReactElement {
  const { block } = props;
  const settled = "kind" in block;
  const isError = settled && block.isError;
  const reportText = reportTextFromBlock(block);
  const [audit, setAudit] = useState<AuditData | undefined>(undefined);
  const [failed, setFailed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [ignored, setIgnored] = useState<ReadonlySet<string>>(new Set());
  const [modal, setModal] = useState<ModalSpec | undefined>(undefined);
  const [rawOpen, setRawOpen] = useState(false);
  const [suppressedModes, setSuppressedModes] = useState<ReadonlySet<string>>(new Set());

  const text = textFromBlock(block);

  const refresh = useCallback((): void => {
    if (text === undefined) return;
    fetch("/api/citation-auditor/audit", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ text }),
    })
      .then((r) => (r.ok ? (r.json() as Promise<AuditData>) : Promise.reject(new Error(String(r.status)))))
      .then((d) => {
        if (d.ok) {
          setAudit(d);
          setFailed(false);
        } else {
          setFailed(true);
        }
      })
      .catch(() => setFailed(true));
  }, [text]);

  useEffect(() => {
    if (settled && !isError) refresh();
  }, [settled, isError, refresh]);

  /** 名单写入 + 刷新。host 端点不可用时保持原状（failed 已有提示）。 */
  const mutate = useCallback(
    (op: "block" | "unblock" | "whitelist" | "unwhitelist", domain: string): void => {
      setBusy(true);
      fetch("/api/citation-auditor/list", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ op, domain }),
      })
        .then(() => refresh())
        .catch(() => {})
        .finally(() => setBusy(false));
    },
    [refresh],
  );

  const addBlocklist = useCallback(
    (v: AuditVerdict): void => {
      // 弹窗被"仅保存"抑制过（本会话不再提示）→ 直接写入
      if (audit?.blocklistEnabled || suppressedModes.has(audit?.mode ?? "")) {
        mutate("block", v.domain);
        return;
      }
      setModal({
        title: `⚠️ 当前模式（${MODE_LABEL[audit?.mode ?? "normal"]}）未启用拦截名单`,
        body: `域名 ${v.domain} 已可保存到拦截名单，但在当前模式下不会被应用。\n要现在开启该模式的拦截名单吗？`,
        buttons: [
          {
            label: "开启并保存",
            onClick: () => {
              const field = BLOCKLIST_FIELD[audit?.mode ?? "normal"];
              // 经插件自有 /settings 端点直接置位（settings 服务命名空间在当前宿主不可靠）
              fetch("/api/citation-auditor/settings", {
                method: "POST",
                headers: { "content-type": "application/json" },
                body: JSON.stringify({ [field]: true }),
              }).catch(() => {});
              mutate("block", v.domain);
              setModal(undefined);
            },
          },
          {
            label: "仅保存",
            onClick: () => {
              setSuppressedModes((s) => new Set([...s, audit?.mode ?? ""]));
              mutate("block", v.domain);
              setModal(undefined);
            },
          },
          { label: "取消", onClick: () => setModal(undefined) },
        ],
      });
    },
    [audit, mutate, suppressedModes],
  );

  const confirmRemove = useCallback(
    (what: string, domain: string, op: "unblock" | "unwhitelist"): void => {
      setModal({
        title: `移除 ${domain}`,
        body: `确定把 ${domain} 从${what}移除吗？`,
        buttons: [
          {
            label: "确认移除",
            onClick: () => {
              mutate(op, domain);
              setModal(undefined);
            },
          },
          { label: "取消", onClick: () => setModal(undefined) },
        ],
      });
    },
    [mutate],
  );

  const openDomain = useCallback((domain: string): void => {
    window.open(`https://${domain}`, "_blank", "noopener,noreferrer");
  }, []);

  // 运行中 / 出错 / 拿不到入参文本：退化为轻量行或纯报表展示
  if (!settled) {
    return (
      <div style={{ ...box, color: "gray" }} data-tool="citation_audit">
        {"⏳ 引用来源审计中…"}
      </div>
    );
  }
  if (isError) {
    return (
      <div style={{ ...box, color: "#e05555" }} data-tool="citation_audit" data-state="error">
        {reportText ?? "citation_audit 执行失败"}
      </div>
    );
  }

  const reportBody = (
    <>
      <div>
        <button type="button" style={dimButton} onClick={() => setRawOpen((v) => !v)}>
          {rawOpen ? "▾ 原始报表" : "▸ 原始报表"}
        </button>
      </div>
      {rawOpen && reportText !== null ? <pre style={{ margin: "6px 0 0", font: "inherit" }}>{reportText}</pre> : null}
    </>
  );

  if (failed) {
    return (
      <div style={box} data-tool="citation_audit" data-state="fallback">
        <div style={dim}>交互报表不可用：host 数据端点不可达。以下为纯文本报表（模型可见内容一致）。</div>
        {reportText !== null ? <pre style={{ margin: "6px 0 0", font: "inherit" }}>{reportText}</pre> : reportBody}
      </div>
    );
  }

  if (audit === undefined) {
    return (
      <div style={{ ...box, color: "gray" }} data-tool="citation_audit">
        {reportText ?? "⏳ 引用来源审计中…"}
      </div>
    );
  }

  if (!audit.enabled) {
    return (
      <div style={{ ...box, color: "gray" }} data-tool="citation_audit">
        {"插件已休眠（设置里可重新开启）。"}
        {reportBody}
      </div>
    );
  }

  const shown = audit.verdicts.filter((v) => !ignored.has(v.domain));

  return (
    <div style={box} data-tool="citation_audit" data-mode={audit.mode}>
      <div>{"════════════════════════════════════════════"}</div>
      <div>{`📊 引用来源威胁度分析（${shown.length}个域名，按威胁度降序）`}</div>
      <div>{"════════════════════════════════════════════"}</div>
      {shown.length === 0 ? <div style={dim}>（无域名，或全部已被忽略）</div> : null}
      {shown.map((v) => {
        const colored = { color: LEVEL_COLOR[v.level] };
        return (
          <div key={v.domain} style={{ margin: "6px 0" }}>
            <div>
              <span style={colored}>{LEVEL_LABEL[v.level]}</span>
              {` ${v.score}分  `}
              <button type="button" style={link} title="新标签打开" onClick={() => openDomain(v.domain)}>
                {v.domain}
              </button>
            </div>
            {v.reasons.length > 0 ? <div style={{ paddingLeft: "1.5em" }}>原因: {v.reasons.join(" + ")}</div> : null}
            <div style={{ paddingLeft: "1.5em", ...dim }}>
              {`来源类型: ${v.sourceKind}`}
              {v.creationDate !== undefined ? `（创建于 ${v.creationDate.slice(0, 10)}）` : ""}
            </div>
            {v.level !== "trusted" ? (
              <div style={{ paddingLeft: "1.5em", marginTop: 2 }}>
                {v.inBlocklist ? (
                  <button
                    type="button"
                    style={dimButton}
                    disabled={busy}
                    onClick={() => confirmRemove("拦截名单", v.domain, "unblock")}
                  >
                    ✓ 已拦截
                  </button>
                ) : (
                  <button type="button" style={button} disabled={busy} onClick={() => addBlocklist(v)}>
                    ➕ 加入拦截名单
                  </button>
                )}
                {v.inWhitelist ? (
                  <button
                    type="button"
                    style={dimButton}
                    disabled={busy}
                    onClick={() => confirmRemove("白名单", v.domain, "unwhitelist")}
                  >
                    ✓ 已白名单
                  </button>
                ) : (
                  <button
                    type="button"
                    style={button}
                    disabled={busy}
                    onClick={() => mutate("whitelist", v.domain)}
                  >
                    ➕ 加入白名单
                  </button>
                )}
                <button
                  type="button"
                  style={dimButton}
                  onClick={() => setIgnored((s) => new Set([...s, v.domain]))}
                >
                  忽略
                </button>
              </div>
            ) : null}
          </div>
        );
      })}
      {reportBody}
      {modal !== undefined ? (
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
          onClick={() => setModal(undefined)}
        >
          <div
            style={{ ...box, background: "var(--bg-color, #1e1e1e)", color: "var(--fg-color, #ddd)", maxWidth: 460 }}
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
      ) : null}
    </div>
  );
}
