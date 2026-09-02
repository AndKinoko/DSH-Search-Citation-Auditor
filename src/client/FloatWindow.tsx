/**
 * 最近回复网址悬浮窗（Phase 4 + 交互扩展）：可拖动的悬浮球 + 展开面板。
 *
 * 面板功能：
 *  - 实时显示最近一次 AI 回复里的网址与威胁分数（/api/citation-auditor/audit）
 *  - 每条非可信域名带名单操作按钮：[➕ 加入拦截名单] / [✓ 已拦截 → 确认移除]、
 *    [➕ 加入白名单] / [✓ 已白名单]、[忽略]——按钮状态机与 Phase 3 交互报表一致
 *  - ⚙ 设置入口：面板内嵌设置视图（检测模式三选一 + 每模式开关 + 年龄查询
 *    测试 + 打开名单文件），写入走插件自有 /api/citation-auditor/settings
 *    端点直接落盘 settings.json（唯一真源，不依赖 harness 的 settings 服务）。
 *    说明：dsh 设置壳的打开状态是组件内部 state，没有跨插件编程式打开 API
 *    （Phase 3 已核实），所以"设置入口"以内嵌视图实现，自包含不依赖壳。
 *
 * 挂载与形态照抄 dsh-pet（MIT，PetSprite + PetDockEntry 模式）：不走
 * session slot——官方 shell 没有根级全局槽位，slot 挂载在新会话页会消失；
 * 直接在 document.body 建容器 + createRoot，页面生命周期单实例。
 * 拖拽用 pointer 事件 + right/bottom 定位 + 视口内 clamp，
 * 位移小于 4px 视为点击，拖拽结束持久化到 localStorage。
 *
 * 分数不把 scorer 打包进 bundle：同一份文本走 host 的
 * /api/citation-auditor/audit（与 citation_audit 工具、Phase 3 交互报表
 * 同一条管道），模式、名单、年龄缓存天然一致。
 */
import { useCallback, useEffect, useMemo, useRef, useState, useSyncExternalStore } from "react";
import { createRoot } from "react-dom/client";
import type { ClientContext, ISessions } from "@deepseek-ai/dsh-client-runtime/client";
import type { SessionId } from "@deepseek-ai/dsh-client-connection/client";
// Type-only：拉 Context 合并（ctx.uiConversation 服务面），运行时零依赖
import type {} from "@deepseek-ai/dsh-client-ui-conversation/client";
import {
  isConversationSettled,
  settledAssistantText,
  type ChatLegacyLike,
  type FloatLikeSnapshot,
} from "./floatData.js";
import { LEVEL_LABEL, type Level } from "../auditor/types.js";
import type { CitationSettingsSection } from "../settingsSection.js";

/** /api/citation-auditor/audit 负载里的单条判决（含按钮状态机需要的名单隶属）。 */
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

/** /api/citation-auditor/audit 的负载。 */
interface AuditData {
  ok: boolean;
  enabled: boolean;
  mode: CitationSettingsSection["mode"];
  blocklistEnabled: boolean;
  summary: string;
  verdicts: AuditVerdict[];
}

/** /api/citation-auditor/status 的负载（设置视图数据）。 */
interface StatusData {
  ok: boolean;
  settings: CitationSettingsSection;
  counts: { whitelist: number; blocklist: number };
  files: Record<string, string>;
  ageQueryReady: boolean;
}

/** 弹窗描述：标题 + 正文 + 按钮组。 */
interface ModalSpec {
  title: string;
  body: string;
  buttons: { label: string; onClick: () => void }[];
}

/** 悬浮窗位置：right/bottom 锚定（窗口缩放时天然贴边）。 */
interface FloatPos {
  right: number;
  bottom: number;
}

const POS_KEY = "citation-auditor-float-pos";
const OPEN_KEY = "citation-auditor-float-open";
const DEFAULT_POS: FloatPos = { right: 24, bottom: 24 };
/** 视口内边距与悬浮球占位（clamp 用的最小/最大余量）。 */
const MARGIN = 12;
const BALL_SIZE = 44;

const MONO = "ui-monospace, SFMono-Regular, Consolas, 'Courier New', monospace";

const LEVEL_COLOR: Record<Level, string> = {
  trusted: "#58a65c",
  suspicious: "#d98a2b",
  warning: "#d9a036",
  critical: "#e05555",
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
  marginTop: 2,
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

/** 模式 → 设置文档里对应"该模式拦截名单开关"的字段名（弹窗"开启并保存"用）。 */
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

function clamp(v: number, lo: number, hi: number): number {
  return Math.min(Math.max(v, lo), Math.max(lo, hi));
}

function loadPos(): FloatPos {
  try {
    const raw = window.localStorage.getItem(POS_KEY);
    if (raw === null) return { ...DEFAULT_POS };
    const parsed = JSON.parse(raw) as Partial<FloatPos>;
    if (typeof parsed.right === "number" && typeof parsed.bottom === "number") {
      return { right: parsed.right, bottom: parsed.bottom };
    }
  } catch {
    // 损坏的持久化数据按默认位置处理
  }
  return { ...DEFAULT_POS };
}

function savePos(pos: FloatPos): void {
  try {
    window.localStorage.setItem(POS_KEY, JSON.stringify(pos));
  } catch {
    // 存储不可用（隐私模式等）就只在本次会话生效
  }
}

function loadOpen(): boolean {
  try {
    return window.localStorage.getItem(OPEN_KEY) === "1";
  } catch {
    return false;
  }
}

/** 无会话时的空快照常量（订阅骨架要求的稳定引用）。 */
const EMPTY_SNAPSHOT: FloatLikeSnapshot = { running: false, partial: null, nodes: [] };

/**
 * 宿主 uiConversation 服务的宽松结构（新宿主对话内容通道）。只读
 * binding(id).target('chat') 快照的 legacy 层，不 import 宿主 UI 内部类型。
 */
interface UiConversationLike {
  binding(id: SessionId): { target(name: string): { getSnapshot(): unknown | undefined; subscribe(fn: () => void): () => void } | undefined } | undefined;
}

/** ChatSnapshot.legacy 的宽松投影（见 floatData.ChatLegacyLike）。 */
interface ChatTargetSnapLike {
  legacy?: ChatLegacyLike;
}

/** 悬浮窗本体：由 mountFloatWindow 挂到 document.body 的独立 React 根上。 */
export function CitationAuditorFloatWindow(props: {
  sessions: ISessions;
  uiConversation?: UiConversationLike;
}): React.ReactElement {
  const { sessions, uiConversation } = props;

  // 当前会话 id（列表快照；切会话/无会话都会推新快照）
  const list = useSyncExternalStore(
    useMemo(() => sessions.list.subscribe.bind(sessions.list), [sessions]),
    useMemo(() => sessions.list.getSnapshot.bind(sessions.list), [sessions]),
  );
  const current: SessionId | undefined = list.current;
  const binding = useMemo(
    () => (current !== undefined ? sessions.binding(current) : undefined),
    [sessions, current],
  );

  // 新宿主：对话内容在 uiConversation 的 chat target（订阅即激活 target）。
  // 旧宿主：无该服务时回退 binding.session 快照的自带 nodes。
  const chatTarget = useMemo(() => {
    if (current === undefined || uiConversation === undefined) return undefined;
    try {
      return uiConversation.binding(current)?.target("chat");
    } catch {
      return undefined;
    }
  }, [uiConversation, current]);

  // 会话级快照：running 信号 + 旧宿主兜底（getSnapshot 引用稳定，来自宿主 observable）
  const sessionSnap = useSyncExternalStore(
    useCallback(
      (fn: () => void) => binding?.session.subscribe(fn) ?? (() => {}),
      [binding],
    ),
    useCallback(() => binding?.session.getSnapshot() ?? EMPTY_SNAPSHOT, [binding]),
  ) as FloatLikeSnapshot;

  // 对话内容快照：新宿主 chat target 的 legacy；不可用（旧宿主）时取 undefined
  const chatSnap = useSyncExternalStore(
    useCallback(
      (fn: () => void) => {
        if (chatTarget === undefined) return () => {};
        try {
          const un = chatTarget.subscribe(fn);
          return typeof un === "function" ? un : () => {};
        } catch {
          return () => {};
        }
      },
      [chatTarget],
    ),
    useCallback(() => {
      if (chatTarget === undefined) return undefined;
      try {
        const snap = chatTarget.getSnapshot() as ChatTargetSnapLike | undefined;
        return snap && typeof snap === "object" && snap.legacy && typeof snap.legacy === "object"
          ? snap.legacy
          : undefined;
      } catch {
        return undefined;
      }
    }, [chatTarget]),
  );

  // 统一视图：节点取 chat.legacy.nodes（新宿主）→ 会话快照 nodes（旧宿主）
  const running = sessionSnap.running === true;
  const nodes = chatSnap?.nodes !== undefined ? chatSnap.nodes : sessionSnap.nodes ?? [];
  const partial = chatSnap !== undefined ? chatSnap.partial : sessionSnap.partial ?? null;

  const snapshot: FloatLikeSnapshot = {
    running,
    partial,
    nodes,
    legacy: chatSnap,
  };

  const settled = isConversationSettled(snapshot);
  const text = useMemo(() => settledAssistantText(nodes), [nodes]);

  const [audit, setAudit] = useState<AuditData | undefined>(undefined);
  const [failed, setFailed] = useState(false);
  const [analyzing, setAnalyzing] = useState(false);
  const auditedTextRef = useRef<string | null>(null);

  // 回合定稿且文本变化 → 防抖 800ms 后重审计（流式期间不请求）
  useEffect(() => {
    if (!settled || text === null || text === auditedTextRef.current) return;
    setAnalyzing(true);
    const timer = setTimeout(() => {
      auditedTextRef.current = text;
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
        .catch(() => setFailed(true))
        .finally(() => setAnalyzing(false));
    }, 800);
    return () => clearTimeout(timer);
  }, [settled, text]);

  const refresh = useCallback((): void => {
    if (text === null) return;
    auditedTextRef.current = text;
    setAnalyzing(true);
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
      .catch(() => setFailed(true))
      .finally(() => setAnalyzing(false));
  }, [text]);

  // ---- 设置视图数据（/status）----
  const [settingsData, setSettingsData] = useState<StatusData | undefined>(undefined);
  const [settingsFailed, setSettingsFailed] = useState(false);
  const fetchSettings = useCallback((): void => {
    fetch("/api/citation-auditor/status")
      .then((r) => (r.ok ? (r.json() as Promise<StatusData>) : Promise.reject(new Error(String(r.status)))))
      .then((d) => {
        if (d.ok) {
          setSettingsData(d);
          setSettingsFailed(false);
        } else {
          setSettingsFailed(true);
        }
      })
      .catch(() => setSettingsFailed(true));
  }, []);

  // 名单操作（与 Phase 3 交互报表同一底层 /list 端点）
  const [busy, setBusy] = useState(false);
  const [ignored, setIgnored] = useState<ReadonlySet<string>>(new Set());
  const [suppressedModes, setSuppressedModes] = useState<ReadonlySet<string>>(new Set());
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

  // 设置写入：走插件自有 /settings 端点（落盘 settings.json 唯一真源），不依赖 settings 服务
  const writeSettings = useCallback((field: keyof CitationSettingsSection, value: boolean | CitationSettingsSection["mode"]): void => {
    fetch("/api/citation-auditor/settings", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ [field]: value }),
    })
      .then(() => {
        // 落盘是异步，稍等再拉 status/audit 保持显示一致
        setTimeout(() => {
          fetchSettings();
          refresh();
        }, 300);
      })
      .catch(() => {
        setTimeout(() => {
          fetchSettings();
          refresh();
        }, 300);
      });
  }, [fetchSettings, refresh]);

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
              writeSettings(field, true);
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
    [audit, mutate, writeSettings, suppressedModes],
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

  const [modal, setModal] = useState<ModalSpec | undefined>(undefined);

  const openDomain = useCallback((domain: string): void => {
    window.open(`https://${domain}`, "_blank", "noopener,noreferrer");
  }, []);

  // 设置写入：走插件自有 /settings 端点（落盘 settings.json 唯一真源），不依赖 settings 服务
  const setSetting = useCallback(
    (field: keyof CitationSettingsSection, value: boolean | CitationSettingsSection["mode"]): void => {
      writeSettings(field, value);
    },
    [writeSettings],
  );

  const testAge = useCallback((): void => {
    setAgeTest({ running: true, result: null });
    fetch("/api/citation-auditor/test-age", { method: "POST" })
      .then((r) => (r.ok ? (r.json() as Promise<{ ok: boolean; creationDate?: string; error?: string }>) : Promise.reject(new Error(String(r.status)))))
      .then((d) => {
        setAgeTest({
          running: false,
          result: d.ok ? `✓ wikipedia.org 创建于 ${d.creationDate}` : `✗ ${d.error ?? "未知错误"}`,
        });
      })
      .catch((err: unknown) => {
        setAgeTest({ running: false, result: `✗ ${err instanceof Error ? err.message : String(err)}` });
      });
  }, []);

  const openFile = useCallback((file: string): void => {
    fetch("/api/citation-auditor/open-file", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ file }),
    }).catch(() => {});
  }, []);

  const [ageTest, setAgeTest] = useState<{ running: boolean; result: string | null }>({ running: false, result: null });

  // ---- 位置与拖拽（dsh-pet PetSprite 模式）----
  const [pos, setPos] = useState<FloatPos>(loadPos);
  const [open, setOpen] = useState(loadOpen);
  const [settingsView, setSettingsView] = useState(false);
  const dragRef = useRef<{ x: number; y: number; right: number; bottom: number; moved: boolean } | null>(null);

  const bindDrag = useCallback(
    (onTap: () => void) => ({
      onPointerDown: (e: React.PointerEvent): void => {
        if (e.button !== 0) return;
        if (e.target !== e.currentTarget && (e.target as HTMLElement).closest("button") !== null) return;
        e.currentTarget.setPointerCapture(e.pointerId);
        dragRef.current = { x: e.clientX, y: e.clientY, right: pos.right, bottom: pos.bottom, moved: false };
      },
      onPointerMove: (e: React.PointerEvent): void => {
        const drag = dragRef.current;
        if (drag === null) return;
        const dx = e.clientX - drag.x;
        const dy = e.clientY - drag.y;
        if (!drag.moved && Math.max(Math.abs(dx), Math.abs(dy)) > 4) drag.moved = true;
        if (!drag.moved) return;
        setPos({
          right: clamp(drag.right - dx, MARGIN, window.innerWidth - BALL_SIZE - MARGIN),
          bottom: clamp(drag.bottom - dy, MARGIN, window.innerHeight - BALL_SIZE - MARGIN),
        });
      },
      onPointerUp: (e: React.PointerEvent): void => {
        const drag = dragRef.current;
        dragRef.current = null;
        e.currentTarget.releasePointerCapture(e.pointerId);
        if (drag === null) return;
        if (drag.moved) {
          savePos(pos);
        } else {
          onTap();
        }
      },
    }),
    [pos],
  );

  const toggleOpen = useCallback((v: boolean): void => {
    setOpen(v);
    try {
      window.localStorage.setItem(OPEN_KEY, v ? "1" : "0");
    } catch {
      // 同 savePos：存不上就只管当前
    }
  }, []);

  const ballDrag = useMemo(() => bindDrag(() => toggleOpen(true)), [bindDrag, toggleOpen]);
  const headerDrag = useMemo(() => bindDrag(() => {}), [bindDrag]);

  const verdicts = audit?.verdicts ?? [];
  const nonTrusted = verdicts.filter((v) => v.level !== "trusted").length;
  const dotColor = failed
    ? "#e05555"
    : nonTrusted > 0
      ? LEVEL_COLOR.critical
      : verdicts.length > 0
        ? LEVEL_COLOR.trusted
        : "#888";

  const shown = verdicts.filter((v) => !ignored.has(v.domain));
  const s = settingsData?.settings;

  return (
    <>
      {!open ? (
        // 悬浮球：拖拽移动，点击展开
        <div
          data-citation-auditor-ball
          onPointerDown={ballDrag.onPointerDown}
          onPointerMove={ballDrag.onPointerMove}
          onPointerUp={ballDrag.onPointerUp}
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
      ) : (
        // 展开面板：标题栏拖拽；正文 = 设置视图 或 审计列表（含名单操作按钮）
        <div
          data-citation-auditor-panel
          style={{
            position: "fixed",
            right: pos.right,
            bottom: pos.bottom,
            width: 380,
            maxHeight: "60vh",
            display: "flex",
            flexDirection: "column",
            background: "var(--bg-color, #1e1e1e)",
            color: "var(--fg-color, #ddd)",
            border: "1px solid #555",
            borderRadius: 6,
            boxShadow: "0 4px 18px rgba(0,0,0,0.4)",
            fontFamily: MONO,
            fontSize: 13,
            zIndex: 2147483000,
            overflow: "hidden",
          }}
        >
          <div
            onPointerDown={headerDrag.onPointerDown}
            onPointerMove={headerDrag.onPointerMove}
            onPointerUp={headerDrag.onPointerUp}
            style={{
              display: "flex",
              alignItems: "center",
              gap: 8,
              padding: "6px 10px",
              borderBottom: "1px solid #444",
              cursor: "grab",
              userSelect: "none",
              touchAction: "none",
            }}
          >
            <span>{settingsView ? "⚙ 引用来源设置" : "🛡 引用来源"}</span>
            <span style={{ flex: 1 }} />
            <button
              type="button"
              title={settingsView ? "返回报表" : "设置"}
              style={{
                background: "none",
                border: "1px solid currentcolor",
                borderRadius: 3,
                color: "inherit",
                cursor: "pointer",
                font: "inherit",
                fontSize: 12,
                padding: "0 6px",
              }}
              onClick={() => {
                setSettingsView((v) => !v);
                if (!settingsView) fetchSettings();
              }}
            >
              {settingsView ? "◀" : "⚙"}
            </button>
            {!settingsView ? (
              <button
                type="button"
                title="重新分析最近回复"
                style={{
                  background: "none",
                  border: "1px solid currentcolor",
                  borderRadius: 3,
                  color: "inherit",
                  cursor: "pointer",
                  font: "inherit",
                  fontSize: 12,
                  padding: "0 6px",
                }}
                onClick={refresh}
              >
                ↻
              </button>
            ) : null}
            <button
              type="button"
              title="收起"
              style={{
                background: "none",
                border: "1px solid currentcolor",
                borderRadius: 3,
                color: "inherit",
                cursor: "pointer",
                font: "inherit",
                fontSize: 12,
                padding: "0 6px",
              }}
              onClick={() => toggleOpen(false)}
            >
              —
            </button>
          </div>

          {settingsView ? (
            // ---- 设置视图（面板内嵌；经 settings scope 写入，与设置卡片同链路）----
            <div style={{ overflowY: "auto", padding: "8px 10px", lineHeight: 1.7 }}>
              {settingsFailed ? (
                <div style={{ color: "#e05555" }}>设置端点不可达（host 端点未就绪）。</div>
              ) : s === undefined ? (
                <div style={dim}>加载设置中…</div>
              ) : (
                <>
                  <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                    <span>插件</span>
                    <button
                      type="button"
                      style={s.enabled ? dimButton : button}
                      onClick={() => setSetting("enabled", !s.enabled)}
                    >
                      {s.enabled ? "✓ 启用中（点击休眠）" : "已休眠（点击启用）"}
                    </button>
                  </div>
                  <div style={{ marginTop: 6 }}>
                    <div style={dim}>检测模式</div>
                    {(Object.keys(MODE_LABEL) as CitationSettingsSection["mode"][]).map((m) => (
                      <label key={m} style={{ display: "block", cursor: "pointer" }}>
                        <input
                          type="radio"
                          name="ca-float-mode"
                          checked={s.mode === m}
                          onChange={() => setSetting("mode", m)}
                        />
                        {` ${MODE_LABEL[m]}`}
                      </label>
                    ))}
                  </div>
                  <div style={{ marginTop: 6 }}>
                    <div style={dim}>拦截名单（每模式独立开关）</div>
                    <label style={{ display: "block", cursor: "pointer" }}>
                      <input
                        type="checkbox"
                        checked={s.blocklistEnabledWhitelist}
                        onChange={(e) => setSetting("blocklistEnabledWhitelist", e.target.checked)}
                      />
                      {" 白名单模式"}
                    </label>
                    <label style={{ display: "block", cursor: "pointer" }}>
                      <input
                        type="checkbox"
                        checked={s.blocklistEnabledNormal}
                        onChange={(e) => setSetting("blocklistEnabledNormal", e.target.checked)}
                      />
                      {" 普通模式"}
                    </label>
                    <label style={{ display: "block", cursor: "pointer" }}>
                      <input
                        type="checkbox"
                        checked={s.blocklistEnabledSimple}
                        onChange={(e) => setSetting("blocklistEnabledSimple", e.target.checked)}
                      />
                      {" 简单模式"}
                    </label>
                    <label style={{ display: "block", cursor: "pointer" }}>
                      <input
                        type="checkbox"
                        checked={s.whitelistEnabledNormal}
                        onChange={(e) => setSetting("whitelistEnabledNormal", e.target.checked)}
                      />
                      {" 普通模式白名单免查加速"}
                    </label>
                  </div>
                  <div style={{ marginTop: 6 }}>
                    <div style={dim}>年龄查询</div>
                    <label style={{ display: "block", cursor: "pointer" }}>
                      <input
                        type="checkbox"
                        checked={s.ageQueryEnabled}
                        onChange={(e) => setSetting("ageQueryEnabled", e.target.checked)}
                      />
                      {" 启用（ageQuery.js）"}
                    </label>
                    <div style={{ marginTop: 2 }}>
                      <button type="button" style={button} onClick={testAge} disabled={ageTest.running}>
                        {ageTest.running ? "测试中…" : "测试（wikipedia.org）"}
                      </button>
                      {ageTest.result !== null ? <span style={dim}>{ageTest.result}</span> : null}
                    </div>
                  </div>
                  <div style={{ marginTop: 6 }}>
                    <div style={dim}>{`名单: 白名单 ${settingsData?.counts.whitelist ?? "?"} · 拦截 ${settingsData?.counts.blocklist ?? "?"}`}</div>
                    <div style={{ marginTop: 2 }}>
                      {(["whitelist", "blocklist", "settings", "ageQuery"] as const).map((f) => (
                        <button key={f} type="button" style={button} onClick={() => openFile(f)}>
                          {f === "ageQuery" ? "编辑 ageQuery.js" : `打开 ${f}.json`}
                        </button>
                      ))}
                    </div>
                  </div>
                  <div style={{ ...dim, marginTop: 6, fontSize: 11 }}>
                    文件改完即生效；名单/设置均在 ~/.citation-auditor/ 下，归你所有。
                  </div>
                </>
              )}
            </div>
          ) : (
            // ---- 审计列表 + 名单操作按钮 ----
            <div style={{ overflowY: "auto", padding: "8px 10px", lineHeight: 1.6 }}>
              {analyzing ? <div style={{ color: "gray" }}>⏳ 分析最近回复中…</div> : null}
              {!analyzing && failed ? (
                <div style={{ color: "#e05555" }}>数据端点不可达（host 端点未就绪或已停用）。</div>
              ) : null}
              {!analyzing && !failed && audit !== undefined && !audit.enabled ? (
                <div style={{ color: "gray" }}>插件已休眠（⚙ 设置里可重新开启）。</div>
              ) : null}
              {!analyzing && !failed && audit !== undefined && audit.enabled && shown.length === 0 ? (
                <div style={{ color: "gray" }}>（最近回复里没有网址，或全部已忽略）</div>
              ) : null}
              {!analyzing && !failed && audit === undefined ? (
                <div style={{ color: "gray" }}>等最近一次回复定稿后自动分析。</div>
              ) : null}
              {shown.map((v) => (
                <div key={v.domain} style={{ margin: "4px 0" }}>
                  <div>
                    <span style={{ color: LEVEL_COLOR[v.level] }}>{LEVEL_LABEL[v.level]}</span>
                    {` ${v.score}分  `}
                    <button type="button" style={link} title="新标签打开" onClick={() => openDomain(v.domain)}>
                      {v.domain}
                    </button>
                  </div>
                  {v.reasons.length > 0 || v.creationDate !== undefined ? (
                    <div style={{ paddingLeft: "1.2em", color: "gray", fontSize: 12 }}>
                      {v.reasons.length > 0 ? `原因: ${v.reasons.join(" + ")}` : ""}
                      {v.creationDate !== undefined ? `（创建于 ${v.creationDate.slice(0, 10)}）` : ""}
                    </div>
                  ) : null}
                  {v.level !== "trusted" ? (
                    <div style={{ paddingLeft: "1.2em" }}>
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
              ))}
              {verdicts.length > 0 ? (
                <div style={{ marginTop: 6, color: "gray", fontSize: 11 }}>
                  分数与 citation_audit 工具一致；名单写入立即生效。
                </div>
              ) : null}
            </div>
          )}

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
          ) : null}
        </div>
      )}
    </>
  );
}

/**
 * 把悬浮窗挂到 document.body（页面生命周期单实例）。dsh-pet 模式：
 * client 热重载时旧实例的 fiber 可能还在收尾，先移除旧容器再建新根，
 * 保证页面上只有一个容器。返回卸载函数（当前 apply 不注册卸载，
 * 靠这里的单实例接管保证热重载不叠窗）。
 */
export function mountFloatWindow(ctx: ClientContext): () => void {
  if (typeof document === "undefined") return () => {};
  for (const stale of Array.from(document.querySelectorAll("div[data-citation-auditor-float]"))) {
    stale.remove();
  }
  const container = document.createElement("div");
  container.dataset.citationAuditorFloat = "";
  document.body.appendChild(container);
  const root = createRoot(container);
  // ctx.sessions 的 Context 合并在 host 侧服务类型（dsh-session）与 client
  // runtime 之间同名冲突（skipLibCheck 掩盖声明冲突），使用点显式窄化——
  // dsh-pet 同款处理：as unknown as ISessions
  // uiConversation 已随 client inject 声明（@deepseek-ai/dsh-client-ui-conversation），
  // 此处直接使用注入面；旧宿主缺失该服务时 apply 层不挂载悬浮窗。
  const uiConversation = (ctx as unknown as { uiConversation?: UiConversationLike }).uiConversation;
  root.render(
    <CitationAuditorFloatWindow sessions={ctx.sessions as unknown as ISessions} uiConversation={uiConversation} />,
  );
  return () => {
    root.unmount();
    container.remove();
  };
}
