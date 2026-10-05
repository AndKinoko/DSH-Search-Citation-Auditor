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
import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState, useSyncExternalStore } from "react";
import { createRoot, type Root } from "react-dom/client";
import type { Context } from "@deepseek-ai/cordis";
import type { ISessions } from "@deepseek-ai/dsh-api-session-controller/client";
import type { SessionId } from "@deepseek-ai/dsh-client-connection/client";
// Type-only：拉 Context 合并（ctx.uiConversation 服务面、'chat' target 快照形状），运行时零依赖
import type {} from "@deepseek-ai/dsh-client-ui-conversation/client";
import type {} from "@deepseek-ai/dsh-client-ui-chat/client";
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
import { clamp, fitBounds } from "./float/styles.js";

const POS_KEY = "citation-auditor-float-pos";
const OPEN_KEY = "citation-auditor-float-open";
const DEFAULT_POS: FloatPos = { right: 24, bottom: 24 };
/** 视口内边距（clamp 用的最小余量）。 */
const MARGIN = 12;
/** 展开面板的固定宽度与高度上限——拖拽钳位必须按它算，不能按悬浮球。 */
const PANEL_W = 380;
const PANEL_MAX_H = 0.6;
/**
 * 展开面板里**不允许**触发拖拽的元素：点它们要执行动作，而不是挪窗口。
 *
 * 只排交互控件。刻意不排 `a`：域名是 `<button>`（走 onOpenDomain），不是裸链接。
 * 也没有把非交互文字区标成「可选区让开」：正文是「域名 + 原因」的审计列表，
 * 长按选中不是这里的高频动作，而排除大面积文字后，剩下的可拖面积只剩标题栏与
 * 行间距——回顾起来正是当初「全框可拖没生效」的心理根源。标题栏本身是非交互区，
 * 必然能拖；按钮各自命中本选择器，互不干扰。
 */
const NO_DRAG_SELECTOR = "button, input, select, textarea, [role='button'], [data-no-drag]";

/**
 * 悬浮球自身的标记：它是「拖拽热区 + 点击入口」二合一，**必须**能接收指针事件。
 *
 * 修订记录（阻断级 bug，2026-10-05 实网验证）：悬浮球为做键盘可达性加了
 * `role="button"`，而 role 命中上面那条 NO_DRAG_SELECTOR，于是球把自己排除了：
 *
 *   div[data-citation-auditor-ball][role=button]
 *     └─ span[aria-hidden] 🛡        ← 指针落点
 *
 * `aria-hidden` 只影响读屏，不影响 `closest()`。于是 shouldSkipDrag 恒为 true，
 * `onPointerDown` 早退、不写 `dragRef`，`finish` 又因 `drag === null` 直接返回——
 * `openPanel()` 永不执行：点击与拖拽双双失效，面板再也打不开。
 *
 * 教训写在这里以免复发：NO_DRAG_SELECTOR 的本意是「排掉面板里的操作按钮」，
 * 不是「排掉球自己」。凡是把 role/aria 属性加到**热区根元素**上的可拖元素，
 * 都必须在此显式豁免。aria-* 属性同理无害（不进选择器），但 role 是会进的。
 */
const DRAG_ALWAYS_SELECTOR = "[data-citation-auditor-ball]";

function tuple(b: { lo: number; hi: number }): [number, number] {
  return [b.lo, b.hi];
}

/**
 * 指针事件的合成路径上是否应当跳过拖拽。
 *
 * 判定顺序要紧：先看目标是否落在「永不排除」的热区里，命中就直接放行，
 * 否则再套 NO_DRAG_SELECTOR。反过来写会让热区根元素上的 role 反过来把自己挡掉。
 *
 * 导出供测试直接断言：本函数此前只经由 React 事件间接生效，于是「悬浮球被自己的
 * role 排除」这类阻断级缺陷能在 187 条全绿的测试下溜过去——交互层没有测试网。
 */
export function shouldSkipDrag(target: EventTarget | null, el: Element): boolean {
  if (!(target instanceof Element)) return false;
  if (el.contains(target) === false) return false;
  // 悬浮球整体是热区：球内的图标 span、角标 span 一律放行
  if (target.closest(DRAG_ALWAYS_SELECTOR) !== null) return false;
  return target.closest(NO_DRAG_SELECTOR) !== null;
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

/** SessionBinding 的宽松投影：只要旧宿主兜底路径用的 session 快照源。 */
interface SessionBindingLike {
  session?: {
    subscribe(fn: () => void): () => void;
    getSnapshot(): unknown;
  };
}

/**
 * 为当前会话持有一个独立引用，切换会话时释放上一个。
 *
 * 没有它就拿不到 binding：ISessions.binding(id) 只「借用已 retain 的 generation」，
 * 不自己 retain 就等于没有 generation。reference.ready 是首次历史打开的等待点，
 * 不用 await——快照订阅会在历史到达后自行推送，这里只需要拿到引用对象本身。
 */
function useRetainedSession(
  sessions: ISessions,
  sessionId: SessionId | undefined,
): { sessionId: SessionId; binding: SessionBindingLike } | undefined {
  const [reference, setReference] = useState<{ sessionId: SessionId; binding: SessionBindingLike } | undefined>();
  useEffect(() => {
    if (sessionId === undefined) {
      setReference(undefined);
      return;
    }
    let live = true;
    let held: { release(): void } | undefined;
    try {
      const ref = (sessions as unknown as {
        retain(id: SessionId, opts: { source: string }): { binding: SessionBindingLike; release(): void };
      }).retain(sessionId, { source: CITE_SOURCE });
      held = ref;
      if (live) setReference({ sessionId, binding: ref.binding });
      else ref.release();
    } catch {
      // retain 失败（会话刚被关闭等）：退回借用路径，下面 binding 仍会尝试 sessions.binding。
      if (live) setReference(undefined);
    }
    return () => {
      live = false;
      try {
        held?.release();
      } catch {
        /* 释放失败不应影响切换 */
      }
    };
  }, [sessions, sessionId]);
  // 切换会话时立刻清空，避免旧会话的 binding 被继续使用一帧。
  //
  // 同步性说明：这里的清空只是 state 层面。真正的释放发生在 effect 回收里，
  // 宿主的 publishRetention→list.set 还要再推一轮快照——所以切会话后有一帧
  // 旧引用仍在 retainedBy 里计数。pickCurrentSession 那边已排除自己的 source，
  // 这一帧不会误判；这里的同步清空只是防止 binding 被多用一渲染。
  return reference?.sessionId === sessionId ? reference : undefined;
}

/** ChatSnapshot.legacy 的宽松投影（见 floatData.ChatLegacyLike）。 */
interface ChatTargetSnapLike {
  legacy?: ChatLegacyLike;
}

/** ISessions.list 快照的宽松投影：只要 ids 与 byId 的引用计数。 */
interface SessionListLike {
  current?: SessionId;
  ids?: readonly SessionId[];
  byId?: Readonly<Record<string, { running?: boolean; retainedBy?: Readonly<Partial<Record<string, number>>> }>>;
}

/** 本插件在 retainInfo/retain 里的来源标签（声明合并可扩展，这里用独立标签）。 */
const CITE_SOURCE = "citationAuditorFloat";

/**
 * 从列表快照里挑出「当前正在看的那个会话」。
 *
 * 不能用 ids[0]：0.2.0 的 SessionListState 是 { ids, byId, phase,
 * projectionsBySession }，**没有 current**，导航归视图属主所有。ids 是宿主列表
 * 顺序（通常最近在前），与用户当前打开的是哪个会话无关——切到第二个会话，浮窗
 * 仍在审计第一个，面板显示的是上一段对话的结论且没有任何提示。
 *
 * 可靠信号按优先级：
 *  1. scopeId（调用方经 sessions.scopeOf(ctx) 拿到）：宿主给每个 Agent 作用域挂的
 *     scope 标签，直接点出「这个插件挂在哪个会话的作用域下」。最权威。
 *  2. 他人 retain 计数：宿主里真正渲染某个会话的组件必然 retain 着它，而后台
 *     列表里的会话不会被 retain。这个值随 list 快照一起推，不需要额外订阅。
 *
 * 反自锁：调用方**必须**把浮窗自己的 source 传进来（excludeSource），自己的持有
 * 不算票。否则选错一次就锁死——useRetainedSession 用同一 source 持有选中的会话，
 * 下一次快照里它的 retainedBy 必然非空，形成「选 A→持有 A→A 有计数→继续选 A」
 * 的正反馈。2026-10-06 实测症状：用户切到 B，面板仍在显示 A 的上一条结论。
 */
export function pickCurrentSession(
  list: SessionListLike | undefined,
  opts?: { scopeId?: SessionId; excludeSource?: string },
): SessionId | undefined {
  if (list === undefined) return undefined;
  const ids = Array.isArray(list.ids) ? list.ids : [];
  const byId = list.byId ?? {};
  // 宿主作用域标签最权威：插件自己挂在哪个会话下，就看哪个。
  if (opts?.scopeId !== undefined && ids.includes(opts.scopeId)) return opts.scopeId;
  // 旧宿主若仍带 current 就优先用它。
  if (list.current !== undefined) return list.current;
  const retained = ids.filter((id) => {
    const counts = byId[id]?.retainedBy;
    if (counts === undefined) return false;
    // 自己的持有不算票：只看他人的计数。
    return Object.entries(counts).some(
      ([source, n]) => source !== opts?.excludeSource && typeof n === "number" && n > 0,
    );
  });
  if (retained.length > 0) return retained[0];
  // 全都没人 retain（例如宿主尚未打开任何会话）时退回列表首位，至少不空白。
  return ids[0];
}

/**
 * 扫描请求：序号令牌 + 可取消。
 *
 * 问题见 M9-b：旧实现无 AbortController、无序号令牌，且请求发起前就推进「已审计」
 * 水位；两条回复的请求在飞时，后到的旧响应覆盖新结论；失败的审计也被标记为
 * 「已审计」，下次快照变更时不再触发，于是面板卡在上一条回复的判决旁附一条错误横幅。
 *
 * 现在：每次扫描带单调递增序号，竞态只取最后一次完成；请求体走 AbortController，
 * 新扫描到来时旧请求的网络与回调一并作废；已审计水位只在**成功**后推进——失败永不
 * 推进，下一次快照变更时照常重试。
 */
function useAuditRequest(): {
  analyzing: boolean;
  failed: boolean;
  audit: AuditData | undefined;
  auditedText: string | null;
  request: (text: string) => void;
  retry: () => void;
  reset: () => void;
} {
  const [audit, setAudit] = useState<AuditData | undefined>(undefined);
  const [failed, setFailed] = useState(false);
  const [analyzing, setAnalyzing] = useState(false);
  const [auditedText, setAuditedText] = useState<string | null>(null);
  const seqRef = useRef(0);
  const abortRef = useRef<AbortController | null>(null);
  const lastTextRef = useRef<string | null>(null);

  const request = useCallback((text: string): void => {
    const seq = (seqRef.current += 1);
    abortRef.current?.abort();
    const controller = new AbortController();
    abortRef.current = controller;
    lastTextRef.current = text;
    setAnalyzing(true);
    setFailed(false);
    fetch("/api/citation-auditor/audit", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ text }),
      signal: controller.signal,
    })
      .then((r) => (r.ok ? (r.json() as Promise<AuditData>) : Promise.reject(new Error(String(r.status)))))
      .then((d) => {
        if (seq !== seqRef.current) return; // 旧请求后到，直接丢弃
        if (d.ok) {
          setAuditedText(text); // 只在成功后推进水位
          setAudit(d);
          setFailed(false);
        } else {
          setFailed(true);
        }
      })
      .catch((err: unknown) => {
        if (err instanceof Error && err.name === "AbortError") return; // 被新请求取代，不算失败
        if (seq !== seqRef.current) return;
        setFailed(true); // 水位不动：下次变更照常重试
      })
      .finally(() => {
        if (seq === seqRef.current) setAnalyzing(false);
      });
  }, []);

  const retry = useCallback((): void => {
    if (lastTextRef.current !== null) request(lastTextRef.current);
  }, [request]);

  const reset = useCallback((): void => {
    seqRef.current += 1; // 作废在飞请求
    abortRef.current?.abort();
    abortRef.current = null;
    lastTextRef.current = null;
    setAuditedText(null);
    setAudit(undefined);
    setFailed(false);
    setAnalyzing(false);
  }, []);

  return {
    analyzing,
    failed,
    audit,
    auditedText,
    request,
    retry,
    reset,
  };
}

/** 悬浮窗本体：由 mountFloatWindow 挂到 document.body 的独立 React 根上。 */
export function CitationAuditorFloatWindow(props: {
  sessions: ISessions;
  uiConversation?: UiConversationLike;
  /** 插件挂载点所在的作用域会话（mountFloatWindow 经 sessions.scopeOf(ctx) 读出）。 */
  scopeId?: SessionId;
}): React.ReactElement {
  const { sessions, uiConversation, scopeId } = props;

  // 当前会话 id（列表快照；切会话/无会话都会推新快照）
  //
  // 0.2.0 变更：SessionListState 不再有 `current` —— 该服务注释明说「导航归视图
  // 属主所有」，运行时快照确认为 { ids, byId, phase, projectionsBySession }。
  // 信号按优先级：scopeId（宿主作用域标签，最权威）→ 旧宿主 current →
  // 他人 retain 计数（排除浮窗自己的持有，避免正反馈自锁）→ 列表首位。
  const list = useSyncExternalStore(
    useMemo(() => sessions.list.subscribe.bind(sessions.list), [sessions]),
    useMemo(() => sessions.list.getSnapshot.bind(sessions.list), [sessions]),
  ) as SessionListLike | undefined;

  const current = useMemo(
    () => pickCurrentSession(list, { scopeId, excludeSource: CITE_SOURCE }),
    [list, scopeId],
  );

  // 必须自己 retain：ISessions.binding(id) 的契约是「借用已 retain 的 binding，
  // 不延长生命周期；没有 retained generation 就返回 undefined」。浮窗是独立 React
  // 根，不在宿主的会话作用域里，没人会替它 retain——不自己持有就永远拿不到
  // binding，浮窗就只能一直停在「等最近一次回复定稿后自动分析」。
  const retained = useRetainedSession(sessions, current);

  const binding = useMemo(
    () => (current !== undefined ? (retained?.binding ?? sessions.binding(current)) : undefined),
    [sessions, current, retained],
  );

  // 新宿主：对话内容在 uiConversation 的 chat target（订阅即激活 target）。
  // 旧宿主：无该服务时回退 binding.session 快照的自带 nodes。
  const chatTarget = useMemo(() => {
    if (current === undefined || uiConversation === undefined) return undefined;
    try {
      return uiConversation.binding(current)?.target("chat");
    } catch {
      // 宿主 binding 已失效（会话被关掉 / generation 被释放）。这不是错误路径，
      // 下次 list 快照推送会带着新的 current 重新触发。
      return undefined;
    }
  }, [uiConversation, current, retained]);

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
  const {
    analyzing,
    failed,
    audit: autoAudit,
    auditedText,
    request: requestAudit,
    retry: retryAudit,
    reset: resetAudit,
  } = useAuditRequest();

  // 交互报表数据源 = 自动扫描的结论（refresh 只是同一请求的强制触发）
  const audit = autoAudit;

  // toobig 判据：/audit 路由把 64KB 以上正文直接 400 拒绝，这里的 body 永远整段
  // 发送，而面板的 failed 横幅统称「数据端点不可达」——真正原因是「这段太长」，
  // 用户会对着修 host 端点。单独记一个原因位。
  // 64KB 是 client 与服务端上限共用的预算（见 service.ts 的 MAX_TEXT_CHARS）。
  const toobig =
    failed &&
    text !== null &&
    audit?.enabled !== false &&
    new Blob([text]).size > 64 * 1024;

  // 切会话时重置扫描（旧水位与旧结论一律作废，防止串会话）
  useEffect(() => {
    resetAudit();
  }, [current, resetAudit]);

  // 回合定稿且文本变化 → 防抖 800ms 后重审计（流式期间不请求）
  useEffect(() => {
    if (!settled || text === null || auditedText === text) return;
    const timer = setTimeout(() => requestAudit(text), 800);
    return () => clearTimeout(timer);
  }, [settled, text, auditedText, requestAudit]);

  const refresh = useCallback((): void => {
    if (text === null) return;
    requestAudit(text);
  }, [text, requestAudit]);

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
  //
  // 问题见 M9-c：旧实现 `.then(() => refresh()).catch(() => {})` 对“失败”一律
  // 吞掉——而 fetch 对 4xx 照常 resolve，guardRoute 的 403、`{ok:false}` 的 200
  // 都走了成功分支。用户点「加入拦截名单」后实际什么都没写入，面板却静默刷新，
  // 看起来像成功了。现在：一律先验 body 的 ok，再决定成败，失败给出原因并保留
  // 重试入口（见下方 writeFailed）。
  const [busy, setBusy] = useState(false);
  const [ignored, setIgnored] = useState<ReadonlySet<string>>(new Set());
  const [suppressedModes, setSuppressedModes] = useState<ReadonlySet<string>>(new Set());
  const [writeFailed, setWriteFailed] = useState<string | null>(null);
  const mutate = useCallback(
    (op: "block" | "unblock" | "whitelist" | "unwhitelist", domain: string): void => {
      setBusy(true);
      setWriteFailed(null);
      fetch("/api/citation-auditor/list", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ op, domain }),
      })
        .then((r) =>
          r.ok ? (r.json() as Promise<{ ok: boolean; error?: string }>) : Promise.reject(new Error(`HTTP ${r.status}`)),
        )
        .then((d) => {
          if (d.ok !== true) {
            throw new Error(d.error ?? "unknown");
          }
          refresh();
        })
        .catch((err: unknown) => {
          setWriteFailed(
            `名单写入失败（${err instanceof Error ? err.message : String(err)}），本次没有落盘——请重试或到设置页确认 host 端点状态。`,
          );
        })
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
  const dragRef = useRef<{ x: number; y: number; right: number; bottom: number; moved: boolean; pointerId: number } | null>(null);
  // 最新位置的旁路引用：onPointerUp 要落盘的是「最后一帧」的位置，而闭包里的
  // pos 取自渲染时——末次 setPos 与 pointerup 若落在同一批更新里就会存回旧值。
  const posRef = useRef(pos);
  posRef.current = pos;
  // 面板实测尺寸：拖拽时要按**面板**的占位做钳位，不是按悬浮球，否则整个面板
  // 会被拖出视口（球只有 44px，面板 380px）。量不到时退回到 CSS 的上限值。
  const panelRef = useRef<HTMLDivElement | null>(null);

  const bindDrag = useCallback(
    (onTap: () => void, grip: () => { w: number; h: number }) => {
      const finish = (e: React.PointerEvent, cancelled: boolean): void => {
        const drag = dragRef.current;
        dragRef.current = null;
        // 必须解捕获：否则元素一直抓着指针，后续 move 继续改位置，且 touch 场景
        // 下按钮再也不会收到事件。
        if (e.currentTarget.hasPointerCapture?.(e.pointerId)) {
          e.currentTarget.releasePointerCapture(e.pointerId);
        }
        if (drag === null) return;
        if (drag.moved) {
          savePos(posRef.current);
        } else if (!cancelled) {
          // 位移没超过阈值才算点击。被取消的 pointer（系统手势、浏览器接管、页面
          // 失焦）不能当点击——否则用户点了却什么都没发生，看起来就是「卡住了」。
          onTap();
        }
      };
      return {
        onPointerDown: (e: React.PointerEvent): void => {
          if (e.button !== 0) return;
          // 走合成事件路径：绑定在面板根元素上时，深层子元素的指针事件也会冒泡上来，
          // 用 e.target 判定会漏掉。按 closest() 就近查，与监听位置无关。
          if (shouldSkipDrag(e.nativeEvent.composedPath()[0] ?? e.target, e.currentTarget)) return;
          e.currentTarget.setPointerCapture(e.pointerId);
          dragRef.current = {
            x: e.clientX,
            y: e.clientY,
            right: posRef.current.right,
            bottom: posRef.current.bottom,
            moved: false,
            pointerId: e.pointerId,
          };
        },
        onPointerMove: (e: React.PointerEvent): void => {
          const drag = dragRef.current;
          if (drag === null || drag.pointerId !== e.pointerId) return;
          const dx = e.clientX - drag.x;
          const dy = e.clientY - drag.y;
          if (!drag.moved && Math.max(Math.abs(dx), Math.abs(dy)) > 4) drag.moved = true;
          if (!drag.moved) return;
          const { w, h } = grip();
          const rx = fitBounds(window.innerWidth, w, MARGIN);
          const ry = fitBounds(window.innerHeight, h, MARGIN);
          setPos({
            right: clamp(drag.right - dx, rx.lo, rx.hi),
            bottom: clamp(drag.bottom - dy, ry.lo, ry.hi),
          });
        },
        onPointerUp: (e: React.PointerEvent): void => finish(e, false),
        // 指针被系统取消时必须走同一套收尾，否则 dragRef 与 pointer capture 一起
        // 残留：下一次点击会因 moved 仍为 true 而被当成拖拽，面板再也点不开。
        onPointerCancel: (e: React.PointerEvent): void => finish(e, true),
      };
    },
    [],
  );

  const toggleOpen = useCallback((v: boolean): void => {
    setOpen(v);
    try {
      window.localStorage.setItem(OPEN_KEY, v ? "1" : "0");
    } catch {
      // 同 savePos：存不上就只管当前
    }
  }, []);

  // 面板根元素是 position:fixed 且高度由内容决定（没有 flex:1 的拉伸父级），
  // 所以 offsetHeight 就是真实尺寸——之前用带 flex:1 的 header 去量，量到的是
  // 被压缩后的高度，钳位自然算不准。量不到时退回 CSS 的上限。
  const panelGrip = useCallback((): { w: number; h: number } => {
    const el = panelRef.current;
    const raw = el && el.offsetHeight > 0 ? el.offsetHeight : window.innerHeight * PANEL_MAX_H;
    return {
      w: Math.min(PANEL_W, Math.max(1, window.innerWidth - 2 * MARGIN)),
      h: Math.min(Math.max(1, raw), window.innerHeight * PANEL_MAX_H),
    };
  }, []);

  /** 把当前 pos 收进「面板尺寸」允许的范围内。 */
  const clampPosToPanel = useCallback((): FloatPos => {
    const { w, h } = panelGrip();
    return {
      right: clamp(posRef.current.right, ...tuple(fitBounds(window.innerWidth, w, MARGIN))),
      bottom: clamp(posRef.current.bottom, ...tuple(fitBounds(window.innerHeight, h, MARGIN))),
    };
  }, [panelGrip]);

  /**
   * 展开时先把位置收进可见范围。
   *
   * 这一步是必须的，拖拽钳位救不了它：球可以停在 x≈12（球自己的边界），而面板宽
   * 380px，同一个 right 值会让面板左边缘落到视口外——面板一打开就在屏幕外，而它
   * 的拖拽热区也在屏幕外，用户抓不到任何东西把它拖回来（这就是「卡住」）。
   */
  const openPanel = useCallback((): void => {
    setOpen(true);
    posRef.current = clampPosToPanel();
    setPos(posRef.current);
    savePos(posRef.current);
  }, [clampPosToPanel]);

  // 悬浮球按自身 44px 钳位；面板按实测尺寸钳位，两者共用同一个 pos，切换时不跳动。
  // bindDrag 只管指针拖拽；悬浮球的键盘激活由 FloatBall.onActivate 直接调 openPanel。
  const ballDrag = useMemo(() => bindDrag(openPanel, () => ({ w: BALL_SIZE, h: BALL_SIZE })), [bindDrag, openPanel]);
  const headerDrag = useMemo(() => bindDrag(() => {}, panelGrip), [bindDrag, panelGrip]);

  // 兜底：面板展开后若视口变小（窗口缩放 / 显示器切换），或 pos 来自损坏的
  // 持久化数据，都在这里拉回可见范围。渲染后测量，避免首帧闪一下。
  useLayoutEffect(() => {
    if (!open) return;
    const fixed = clampPosToPanel();
    if (fixed.right !== posRef.current.right || fixed.bottom !== posRef.current.bottom) {
      posRef.current = fixed;
      setPos(fixed);
      savePos(fixed);
    }
  }, [open, settingsView, audit, clampPosToPanel]);

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
          onActivate={openPanel}
          dragHandlers={ballDrag}
        />
      ) : (
        // 展开面板：标题栏拖拽；正文 = 设置视图 或 审计列表（含名单操作按钮）
        <div
          data-citation-auditor-panel
          ref={panelRef}
          // 整个面板都是拖拽热区：空白区、标题栏、列表空白处都能拖。
          onPointerDown={headerDrag.onPointerDown}
          onPointerMove={headerDrag.onPointerMove}
          onPointerUp={headerDrag.onPointerUp}
          onPointerCancel={headerDrag.onPointerCancel}
          style={{
            position: "fixed",
            right: pos.right,
            bottom: pos.bottom,
            width: PANEL_W,
            maxHeight: `${PANEL_MAX_H * 100}vh`,
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
            // 面板整体可拖（绑定在根元素，见上）；正文要能选字，所以 user-select
            // 保持 text。按钮全部命中 NO_DRAG_SELECTOR（点击不拖窗）。
            cursor: "default",
            userSelect: "text",
            // 触屏上默认会先滚动/放大，抢走指针序列，拖拽就断在半路。
            touchAction: "none",
          }}
        >
          <div
            // 拖拽绑定在面板根元素上，整个框都是热区。标题栏**不能**标 data-no-drag：
            // 它排除后，用户最自然会去拖的地方就成了死区，表现为「拖不动」。
            // 标题栏里的按钮各自命中 NO_DRAG_SELECTOR，互不影响。
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
              toobig={toobig === true}
              auditEnabled={audit?.enabled}
              verdicts={verdicts}
              ignored={ignored}
              busy={busy}
              writeFailed={writeFailed}
              onDismissWriteFailed={() => setWriteFailed(null)}
              onRetryAudit={retryAudit}
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
export function mountFloatWindow(ctx: Context): () => void {
  if (typeof document === "undefined") return () => {};
  // 旧实例可能还在页面里（client 热重载时旧 fiber 尚未收尾）。这里**必须 unmount
  // 它的 React root**，只 remove 容器 node 是不够的：React 树仍然存活，副作用与
  // 订阅照旧运行，每次 HMR 就多留一份还在发 /audit 请求的实例。
  for (const stale of Array.from(document.querySelectorAll("div[data-citation-auditor-float]"))) {
    const root = (stale as HTMLElement & { __citationAuditorRoot?: Root }).__citationAuditorRoot;
    try {
      root?.unmount();
    } catch {
      /* 旧 root 可能已被卸载，忽略 */
    }
    stale.remove();
  }
  const container = document.createElement("div");
  container.dataset.citationAuditorFloat = "";
  document.body.appendChild(container);
  const root = createRoot(container);
  (container as HTMLElement & { __citationAuditorRoot?: Root }).__citationAuditorRoot = root;
  // ctx.sessions 的 Context 合并在 host 侧服务类型（dsh-session）与 client
  // runtime 之间同名冲突（skipLibCheck 掩盖声明冲突），使用点显式窄化——
  // dsh-pet 同款处理：as unknown as ISessions
  // uiConversation 已随 client inject 声明（@deepseek-ai/dsh-client-ui-conversation），
  // 此处直接使用注入面；旧宿主缺失该服务时 apply 层不挂载悬浮窗。
  const uiConversation = (ctx as unknown as { uiConversation?: UiConversationLike }).uiConversation;
  // 插件自身的 Context 若挂在某个会话的 Agent 作用域下，scopeOf 直接点出那个 id。
  // 这是「当前会话」最权威的信号（见 pickCurrentSession 的注释）：宿主给每个
  // Agent generation 挂 scope tag，读自己 ctx 上的 tag 即可，不需要猜。
  // 注意跨包直接 import 会内联第二个模块实例、私有 Symbol 对不上（service.d.ts
  // 第 216-218 行有明确警告），所以必须经 ctx.sessions 的方法调用。
  // 挂载点在根上（无 scope）时为 undefined，pickCurrentSession 会退回启发式。
  let scopeId: SessionId | undefined;
  try {
    const sessionsLike = ctx.sessions as unknown as {
      scopeOf?: (c: unknown) => SessionId | undefined;
    };
    scopeId = typeof sessionsLike.scopeOf === "function" ? sessionsLike.scopeOf(ctx) : undefined;
  } catch {
    scopeId = undefined;
  }
  root.render(
    <CitationAuditorFloatWindow
      sessions={ctx.sessions as unknown as ISessions}
      uiConversation={uiConversation}
      scopeId={scopeId}
    />,
  );
  return () => {
    root.unmount();
    container.remove();
  };
}
