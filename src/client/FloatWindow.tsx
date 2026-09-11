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
import type { CitationSettingsSection } from "../settingsSection.js";
import { MONO, BLOCKLIST_FIELD, MODE_LABEL } from "./constants.js";
import {
  FloatBall,
  BALL_SIZE,
  AuditPanel,
  SettingsPanel,
  ConfirmDialog,
  type AuditData,
  type StatusData,
  type ModalSpec,
  type FloatPos,
} from "./float/index.js";
import { clamp } from "./float/styles.js";

const POS_KEY = "citation-auditor-float-pos";
const OPEN_KEY = "citation-auditor-float-open";
const DEFAULT_POS: FloatPos = { right: 24, bottom: 24 };
/** 视口内边距与悬浮球占位（clamp 用的最小/最大余量）。 */
const MARGIN = 12;

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
  const writeSettings = useCallback((field: keyof CitationSettingsSection, value: boolean | number | string): void => {
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
    (v: { domain: string }): void => {
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

  const openFile = useCallback((file: string): void => {
    fetch("/api/citation-auditor/open-file", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ file }),
    }).catch(() => {});
  }, []);

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

  return (
    <>
      {!open ? (
        <FloatBall
          pos={pos}
          nonTrusted={nonTrusted}
          failed={failed}
          hasVerdicts={verdicts.length > 0}
          dragHandlers={ballDrag}
        />
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
            <SettingsPanel
              settingsData={settingsData}
              settingsFailed={settingsFailed}
              onSetSetting={writeSettings}
              onOpenFile={openFile}
            />
          ) : (
            <AuditPanel
              analyzing={analyzing}
              failed={failed}
              auditEnabled={audit?.enabled}
              verdicts={verdicts}
              ignored={ignored}
              busy={busy}
              onAddBlocklist={addBlocklist}
              onConfirmRemove={confirmRemove}
              onAddWhitelist={(domain) => mutate("whitelist", domain)}
              onIgnore={(domain) => setIgnored((s) => new Set([...s, domain]))}
              onOpenDomain={openDomain}
            />
          )}

          {modal !== undefined ? (
            <ConfirmDialog modal={modal} onClose={() => setModal(undefined)} />
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
