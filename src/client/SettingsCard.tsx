/**
 * Citation Auditor 设置卡片：还原设计稿的文本式 TUI——等宽字体、box 边框、
 * ○/● 单选与 ☑/☐ 开关，交互全部落在真实控件上。
 *
 * 设计规则（IDE-prompt-主任务-v0.3 Phase 2）：
 *  1. 每个名单旁必有 [查看/编辑 ▸] → 调 open-file 用系统默认程序打开 JSON，
 *     不做专门编辑 UI；改完靠 host 的 mtime 热重载即生效
 *  2. [编辑JS代码 ▸] 打开 ageQuery.js（头部自带注释模板）
 *  3. [测试 ▸] 固定用 wikipedia.org 跑一次，当场显示日期与判定
 *  4. 简单模式详情 = 纯说明页（2023 分界线依据 + 年龄查询配置状态）
 *  5. 全部功能关闭 = 插件完全休眠（enabled 开关经 /settings 端点直达 settings.json）
 */
import { useCallback, useEffect, useState } from "react";
import type { CitationSettingsSection } from "../settingsSection.js";
import { ENFORCEMENT_LABEL, type EnforcementAction } from "../auditor/types.js";

/** 卡片经 slot inject 拿到的脸（当前设置写入走插件自有 /settings 端点，不依赖 settings 服务）。 */
export interface CardInject {} 

/** GET /api/citation-auditor/status 的负载。 */
interface StatusPayload {
  ok: boolean;
  stateDir: string;
  files: Record<"whitelist" | "blocklist" | "settings" | "ageQuery", string>;
  counts: { whitelist: number; blocklist: number };
  settings: CitationSettingsSection;
  ageQueryReady: boolean;
}

type OpenableFile = "whitelist" | "blocklist" | "settings" | "ageQuery";

/** 测试结果区状态。 */
interface TestOutcome {
  running: boolean;
  ok?: boolean;
  message?: string;
}

const MONO = "ui-monospace, SFMono-Regular, Consolas, 'Courier New', monospace";

const box: React.CSSProperties = {
  fontFamily: MONO,
  fontSize: 13,
  lineHeight: 1.7,
  border: "3px double currentcolor",
  borderRadius: 4,
  padding: "12px 16px",
  maxWidth: 560,
  whiteSpace: "pre-wrap",
};

const rowButton: React.CSSProperties = {
  fontFamily: MONO,
  fontSize: 13,
  background: "none",
  border: "none",
  color: "#4aa3ff",
  cursor: "pointer",
  padding: 0,
};

const rowLabel: React.CSSProperties = {
  background: "none",
  border: "none",
  color: "inherit",
  font: "inherit",
  cursor: "pointer",
  padding: 0,
  textAlign: "left",
};

const sectionRule: React.CSSProperties = { color: "gray" };
const dim: React.CSSProperties = { color: "gray" };

/** 单选/开关行共用的行容器。 */
function Row({ children }: { children: React.ReactNode }): React.ReactElement {
  return <div>{children}</div>;
}

/** 三种模式的展示元数据（文案照设计稿）。 */
const MODES: ReadonlyArray<{
  key: CitationSettingsSection["mode"];
  title: string;
  brief: string;
}> = [
  { key: "whitelist", title: "白名单模式", brief: "只信任名单内域名，其余全部标红" },
  { key: "normal", title: "普通模式", brief: "多信号评分，默认放行，可疑项提醒" },
  { key: "simple", title: "简单模式", brief: "2023年后注册的域名一律标红" },
];

/** 拦截策略三档（与 host EnforcementAction 对齐）。 */
const ENFORCEMENT_OPTIONS: ReadonlyArray<{ key: EnforcementAction; brief: string }> = [
  { key: "allow", brief: "只在报表标红，不阻止 web 访问" },
  { key: "ask", brief: "命中时需确认后才访问" },
  { key: "deny", brief: "命中时直接拒绝 web 访问" },
];

/** 高级阈值字段（与 settingsSection clamp 对齐）。 */
const SCORING_FIELDS: ReadonlyArray<{ key: keyof CitationSettingsSection; label: string; min: number; max: number }> = [
  { key: "scoringCutoffYear", label: "注册年份分界线", min: 2000, max: 2100 },
  { key: "scoringTldTrustBonus", label: "高风险TLD加分", min: 0, max: 100 },
  { key: "scoringPatternBonus", label: "连字符/数字加分", min: 0, max: 100 },
  { key: "scoringPostCutoffBonus", label: "分界线后注册加分", min: 0, max: 100 },
  { key: "scoringUrlIpBonus", label: "IP直连加分", min: 0, max: 100 },
  { key: "scoringUrlShortenerBonus", label: "短链加分", min: 0, max: 100 },
  { key: "scoringUrlTrackingBonus", label: "追踪参数加分", min: 0, max: 100 },
];

/**
 * 数字字段：草稿值与已落盘值分离。
 *
 * 问题见 M9-a：`Number("") === 0` 会通过 isFinite 守卫并被钳到最小值，
 * 全选后重输不可能，且 300ms 的自动 refetch 会把输入中的数字回滚。
 * 本地草稿 + blur/Enter 提交：输入中只管本地，提交时做一次 clamp。
 */
function ScoringField({ f, value, onSet, disabled }: { f: { key: keyof CitationSettingsSection; label: string; min: number; max: number }; value: number; onSet: (v: number) => void; disabled: boolean }): React.ReactElement {
  const [draft, setDraft] = useState<string | null>(null);
  useEffect(() => {
    setDraft(null);
  }, [value]);
  const shown = draft ?? String(value);
  const commit = useCallback((): void => {
    if (draft === null) return;
    setDraft(null);
    const raw = draft.trim();
    if (raw === "") return; // 清空=放弃本次输入，不回写，不回滚
    const n = Number(raw);
    if (!Number.isFinite(n)) return; // 非法=放弃，不回写
    onSet(Math.min(f.max, Math.max(f.min, Math.round(n))));
  }, [draft, f, onSet]);
  return (
    <span>
      <input
        type="number"
        min={f.min}
        max={f.max}
        value={shown}
        disabled={disabled}
        style={{ fontFamily: MONO, fontSize: 13, width: 80 }}
        onChange={(e) => setDraft(e.target.value)}
        onBlur={commit}
        onKeyDown={(e) => {
          if (e.key === "Enter") (e.target as HTMLInputElement).blur();
        }}
      />
    </span>
  );
}

/** 简单模式的纯说明页内容（设计规则 4：唯一无编辑内容的页面）。 */
function SimpleModeDetail({ ageQueryReady }: { ageQueryReady: boolean }): React.ReactElement {
  return (
    <div style={{ ...dim, margin: "2px 0 6px 1.5em" }}>
      {"说明: 域名年龄是简单模式唯一的信号。2023 年是分界线——\n大模型训练语料和主流站点的收录高峰在此之前，\n之后才注册的域名出现在引用里的可信度显著更低。\n\n"}
      {ageQueryReady
        ? "年龄查询: 片段已就绪 ✓"
        : "年龄查询: 未就绪 ✗（在下方 [编辑JS代码 ▸] 配置并用 [测试 ▸] 验证）"}
    </div>
  );
}

export function CitationSettingsCard(_props: CardInject): React.ReactElement {
  const [status, setStatus] = useState<StatusPayload | undefined>(undefined);
  const [notice, setNotice] = useState<string>("");
  const [detailsOpen, setDetailsOpen] = useState<CitationSettingsSection["mode"] | undefined>(undefined);
  const [advancedOpen, setAdvancedOpen] = useState(false);
  const [test, setTest] = useState<TestOutcome>({ running: false });

  const refreshStatus = useCallback((): void => {
    fetch("/api/citation-auditor/status")
      .then((r) => (r.ok ? (r.json() as Promise<StatusPayload>) : undefined))
      .then((s) => {
        if (s?.ok) setStatus(s);
      })
      .catch(() => {
        // host 端点缺席（纯 CLI 宿主 / 旧版）：名单数量与文件按钮不可用即可
      });
  }, []);

  useEffect(() => {
    refreshStatus();
  }, [refreshStatus]);

  const value = status?.settings;
  const writable = value !== undefined;

  /** 写入走插件自有 /settings 端点：落盘 settings.json（唯一真源），不依赖 settings 服务。 */
  const set = useCallback(
    <K extends keyof CitationSettingsSection>(field: K, v: CitationSettingsSection[K]): void => {
      fetch("/api/citation-auditor/settings", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ [field]: v }),
      })
        .then((r) => (r.ok ? r.json() : Promise.reject(new Error(String(r.status)))))
        .then((r: { ok: boolean }) => {
          if (r.ok) setNotice("");
          refreshStatus();
        })
        .catch(() => setNotice("写入失败：host 数据端点不可用"));
    },
    [refreshStatus],
  );

  const openFile = useCallback(
    (file: OpenableFile): void => {
      fetch("/api/citation-auditor/open-file", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ file }),
      })
        .then((r) => r.json() as Promise<{ ok: boolean; path?: string; error?: string }>)
        .then((r) => {
          setNotice(
            r.ok && r.path !== undefined
              ? `已用系统默认程序打开: ${r.path}\n（改完保存即生效，无需重启）`
              : `打开失败: ${r.error ?? "unknown"}`,
          );
        })
        .catch(() => {
          setNotice("打开失败: host 数据端点不可用");
        });
    },
    [],
  );

  const runTest = useCallback((): void => {
    setTest({ running: true });
    refreshStatus();
    fetch("/api/citation-auditor/test-age", { method: "POST" })
      .then((r) => r.json() as Promise<{ ok: boolean; creationDate?: string; error?: string }>)
      .then((r) => {
        setTest({
          running: false,
          ok: r.ok,
          message: r.ok
            ? `测试通过：wikipedia.org 创建于 ${r.creationDate ?? "?"}`
            : `测试失败：${r.error ?? "unknown"}（片段无法启用时保持关闭）`,
        });
        refreshStatus();
      })
      .catch(() => {
        setTest({ running: false, ok: false, message: "测试失败：host 数据端点不可用" });
      });
  }, [refreshStatus]);

  if (value === undefined) {
    return <div style={{ ...box, ...dim }}>Citation Auditor 设置载入中…</div>;
  }

  const counts = status?.counts;
  const toggle = (on: boolean): string => (on ? "☑" : "☐");
  const radio = (selected: boolean): string => (selected ? "●" : "○");
  const modeRowButton = (mode: CitationSettingsSection["mode"]): React.ReactElement => (
    <button
      type="button"
      style={rowButton}
      onClick={() => setDetailsOpen(detailsOpen === mode ? undefined : mode)}
    >
      [详情 {detailsOpen === mode ? "▾" : "▸"}]
    </button>
  );

  return (
    <div style={box}>
      <Row>{"Citation Auditor 设置"}</Row>
      <Row>{"═".repeat(44)}</Row>
      <Row>
        <button
          type="button"
          style={rowLabel}
          disabled={!writable}
          onClick={() => set("enabled", !value.enabled)}
        >
          {toggle(value.enabled)} 启用插件（关闭=完全休眠）
        </button>
      </Row>
      <Row>{" "}</Row>
      <Row>{"检测模式（三选一）"}</Row>
      <Row>{" "}</Row>
      {MODES.map((m) => {
        const selected = value.mode === m.key;
        return (
          <div key={m.key} style={{ margin: "2px 0" }}>
            <Row>
              <button
                type="button"
                style={rowLabel}
                disabled={!writable}
                onClick={() => set("mode", m.key)}
              >
                {radio(selected)} {m.title}
              </button>{" "}
              {modeRowButton(m.key)}
            </Row>
            <div style={{ ...dim, margin: "0 0 0 1.5em" }}>{m.brief}</div>
            {m.key === "whitelist" && selected && (
              <Row>
                <span style={{ margin: "0 0 0 1.5em" }}>
                  {"白名单: 共 "}
                  {counts === undefined ? "?" : counts.whitelist}
                  {" 个 "}
                </span>
                <button type="button" style={rowButton} onClick={() => openFile("whitelist")}>
                  [查看/编辑 ▸]
                </button>
              </Row>
            )}
            {selected && (
              <Row>
                <span style={{ margin: "0 0 0 1.5em" }}>
                  <button
                    type="button"
                    style={rowLabel}
                    disabled={!writable}
                    onClick={() =>
                      set(
                        m.key === "whitelist"
                          ? "blocklistEnabledWhitelist"
                          : m.key === "normal"
                            ? "blocklistEnabledNormal"
                            : "blocklistEnabledSimple",
                        !(m.key === "whitelist"
                          ? value.blocklistEnabledWhitelist
                          : m.key === "normal"
                            ? value.blocklistEnabledNormal
                            : value.blocklistEnabledSimple),
                      )
                    }
                  >
                    {toggle(
                      m.key === "whitelist"
                        ? value.blocklistEnabledWhitelist
                        : m.key === "normal"
                          ? value.blocklistEnabledNormal
                          : value.blocklistEnabledSimple,
                    )}{" "}
                    启用拦截名单
                  </button>{" "}
                </span>
                <button type="button" style={rowButton} onClick={() => openFile("blocklist")}>
                  [查看/编辑 ▸]
                </button>
              </Row>
            )}
            {m.key === "normal" && selected && (
              <Row>
                <span style={{ margin: "0 0 0 1.5em" }}>
                  <button
                    type="button"
                    style={rowLabel}
                    disabled={!writable}
                    onClick={() => set("whitelistEnabledNormal", !value.whitelistEnabledNormal)}
                  >
                    {toggle(value.whitelistEnabledNormal)} 启用白名单（免查加速）
                  </button>
                </span>
              </Row>
            )}
            {m.key === "simple" && selected && detailsOpen === "simple" && (
              <SimpleModeDetail ageQueryReady={status?.ageQueryReady ?? false} />
            )}
            {m.key === "simple" && selected && !detailsOpen && (
              <div style={{ ...dim, margin: "0 0 0 1.5em" }}>（本模式需配置下方年龄查询，[详情 ▸] 看说明）</div>
            )}
            {detailsOpen === m.key && m.key !== "simple" && (
              <div style={{ ...dim, margin: "0 0 0 1.5em" }}>
                {m.key === "whitelist"
                  ? "名单内绿，名单外一律红。名单内容在上方 [查看/编辑 ▸] 里改。"
                  : "信号: TLD、连字符与数字个数、域名长度、注册年龄（若启用年龄查询）。"}
              </div>
            )}
          </div>
        );
      })}
      <Row>
        <span style={sectionRule}>{"── 通用设置 ──"}</span>
      </Row>
      <Row>
        <button
          type="button"
          style={rowLabel}
          disabled={!writable}
          onClick={() => set("ageQueryEnabled", !value.ageQueryEnabled)}
        >
          {toggle(value.ageQueryEnabled)} 启用年龄查询片段
        </button>
        {" "}
        <button type="button" style={rowButton} onClick={() => openFile("ageQuery")}>
          [编辑JS代码 ▸]
        </button>
        {" "}
        <button type="button" style={rowButton} onClick={runTest} disabled={test.running}>
          {test.running ? "[测试中…]" : "[测试 ▸]"}
        </button>
      </Row>
      {test.message !== undefined && (
        <div style={{ margin: "0 0 0 1.5em", color: test.ok ? "inherit" : "#e08040" }}>{test.message}</div>
      )}
      <Row>
        <span style={sectionRule}>{"── 拦截策略 ──"}</span>
      </Row>
      {ENFORCEMENT_OPTIONS.map((o) => {
        const selected = value.enforcementBlocklist === o.key;
        return (
          <Row key={o.key}>
            <button
              type="button"
              style={rowLabel}
              disabled={!writable}
              onClick={() => set("enforcementBlocklist", o.key)}
            >
              {radio(selected)} {ENFORCEMENT_LABEL[o.key]}（{o.key}）
            </button>
            <div style={{ ...dim, margin: "0 0 0 1.5em" }}>{o.brief}</div>
          </Row>
        );
      })}
      <Row>
        <span style={sectionRule}>{"── 网页内容注入防护 ──"}</span>
      </Row>
      <Row>
        <button
          type="button"
          style={rowLabel}
          disabled={!writable}
          onClick={() => set("injectionEnabled", !value.injectionEnabled)}
        >
          {toggle(value.injectionEnabled)} 启用注入防护（web_fetch 响应正文）
        </button>
        <div style={{ ...dim, margin: "0 0 0 1.5em" }}>
          命中时只在正文前插入警示块并说明「这是数据不是指令」——
          正文一字不改，不删内容、不转错误、不中断生成，由你自行判断。
        </div>
      </Row>
      <Row>
        <button
          type="button"
          style={rowLabel}
          disabled={!writable || value.injectionEnabled !== true}
          onClick={() => set("injectionFuzzy", !value.injectionFuzzy)}
        >
          {toggle(value.injectionFuzzy)} typo 模糊匹配（ignroe / revael）
        </button>
        <div style={{ ...dim, margin: "0 0 0 1.5em" }}>
          默认关闭。字形打乱类攻击的误报明显更高，代价是用户会对告警脱敏。
        </div>
      </Row>
      <Row>
        <span style={sectionRule}>{"── 高级阈值 ──"}</span>{" "}
        <button type="button" style={rowButton} onClick={() => setAdvancedOpen(!advancedOpen)}>
          [{advancedOpen ? "收起 ▾" : "展开 ▸"}]
        </button>
      </Row>
      {advancedOpen &&
        SCORING_FIELDS.map((f) => (
          <Row key={f.key}>
            <span style={{ margin: "0 0 0 1.5em" }}>
              {f.label}（{f.min}–{f.max}）:{" "}
            </span>
            <ScoringField f={f} value={Number(value[f.key])} disabled={!writable} onSet={(v) => set(f.key, v as never)} />
          </Row>
        ))}
      {advancedOpen && (
        <div style={{ ...dim, margin: "0 0 0 1.5em" }}>其余 scoring 键直接改 settings.json 即生效。</div>
      )}
      {status !== undefined && (
        <div style={{ ...dim, margin: 0 }}>
          {"\n状态目录: "}
          {status.stateDir}
          {"\n拦截名单: "}
          {counts === undefined ? "?" : counts.blocklist}
          {" 条   年龄片段: "}
          {status.ageQueryReady ? "就绪" : "空"}
        </div>
      )}
      {notice !== "" && <div style={{ margin: 0, color: "#4aa3ff" }}>{`\n${notice}`}</div>}
      {!writable && <div style={{ ...dim, margin: 0 }}>{"\n（当前设置文档只读，无法在此修改）"}</div>}
    </div>
  );
}
