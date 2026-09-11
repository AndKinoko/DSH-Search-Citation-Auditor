/**
 * 设置面板：模式选择、拦截名单开关、年龄查询测试、文件打开。
 */
import React, { useState, useCallback } from "react";
import { MODE_LABEL } from "../constants.js";
import { ENFORCEMENT_LABEL, type EnforcementAction } from "../../auditor/types.js";
import type { CitationSettingsSection } from "../../settingsSection.js";
import type { StatusData } from "./types.js";
import { button, dimButton, dim } from "./styles.js";

interface SettingsPanelProps {
  settingsData: StatusData | undefined;
  settingsFailed: boolean;
  onSetSetting: (field: keyof CitationSettingsSection, value: boolean | number | string) => void;
  onOpenFile: (file: string) => void;
}

/** 拦截策略三档（与 host EnforcementAction 对齐）。 */
const ENFORCEMENT_OPTIONS: ReadonlyArray<EnforcementAction> = ["allow", "ask", "deny"];

/** 高级阈值字段（label + 上下限，与 settingsSection clamp 对齐）。 */
const SCORING_FIELDS: ReadonlyArray<{ key: keyof CitationSettingsSection; label: string; min: number; max: number }> = [
  { key: "scoringCutoffYear", label: "注册年份分界线", min: 2000, max: 2100 },
  { key: "scoringTldTrustBonus", label: "高风险 TLD 加分", min: 0, max: 100 },
  { key: "scoringPatternBonus", label: "连字符/数字加分", min: 0, max: 100 },
  { key: "scoringPostCutoffBonus", label: "分界线后注册加分", min: 0, max: 100 },
  { key: "scoringUrlIpBonus", label: "IP 直连加分", min: 0, max: 100 },
  { key: "scoringUrlShortenerBonus", label: "短链加分", min: 0, max: 100 },
  { key: "scoringUrlTrackingBonus", label: "追踪参数加分", min: 0, max: 100 },
];

export function SettingsPanel({ settingsData, settingsFailed, onSetSetting, onOpenFile }: SettingsPanelProps): React.ReactElement {
  const [ageTest, setAgeTest] = useState<{ running: boolean; result: string | null }>({ running: false, result: null });
  const [advancedOpen, setAdvancedOpen] = useState(false);

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

  const s = settingsData?.settings;

  return (
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
              onClick={() => onSetSetting("enabled", !s.enabled)}
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
                  onChange={() => onSetSetting("mode", m)}
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
                onChange={(e) => onSetSetting("blocklistEnabledWhitelist", e.target.checked)}
              />
              {" 白名单模式"}
            </label>
            <label style={{ display: "block", cursor: "pointer" }}>
              <input
                type="checkbox"
                checked={s.blocklistEnabledNormal}
                onChange={(e) => onSetSetting("blocklistEnabledNormal", e.target.checked)}
              />
              {" 普通模式"}
            </label>
            <label style={{ display: "block", cursor: "pointer" }}>
              <input
                type="checkbox"
                checked={s.blocklistEnabledSimple}
                onChange={(e) => onSetSetting("blocklistEnabledSimple", e.target.checked)}
              />
              {" 简单模式"}
            </label>
            <label style={{ display: "block", cursor: "pointer" }}>
              <input
                type="checkbox"
                checked={s.whitelistEnabledNormal}
                onChange={(e) => onSetSetting("whitelistEnabledNormal", e.target.checked)}
              />
              {" 普通模式白名单免查加速"}
            </label>
          </div>
          <div style={{ marginTop: 6 }}>
            <div style={dim}>拦截策略（命中拦截名单时）</div>
            {ENFORCEMENT_OPTIONS.map((a) => (
              <label key={a} style={{ display: "block", cursor: "pointer" }}>
                <input
                  type="radio"
                  name="ca-float-enforcement"
                  checked={s.enforcementBlocklist === a}
                  onChange={() => onSetSetting("enforcementBlocklist", a)}
                />
                {` ${ENFORCEMENT_LABEL[a]}（${a}）`}
              </label>
            ))}
          </div>
          <div style={{ marginTop: 6 }}>
            <div style={dim}>
              <button
                type="button"
                style={{ ...button, marginRight: 4 }}
                onClick={() => setAdvancedOpen((v) => !v)}
              >
                {advancedOpen ? "高级阈值 ▾" : "高级阈值 ▸"}
              </button>
            </div>
            {advancedOpen ? (
              <div style={{ marginTop: 4 }}>
                {SCORING_FIELDS.map((f) => (
                  <label key={f.key} style={{ display: "block", margin: "2px 0" }}>
                    <span style={{ ...dim, fontSize: 12 }}>{`${f.label} `}</span>
                    <input
                      type="number"
                      min={f.min}
                      max={f.max}
                      value={Number(s[f.key])}
                      style={{ width: 72, fontFamily: "inherit", fontSize: 12 }}
                      onChange={(e) => {
                        const n = Number(e.target.value);
                        if (Number.isFinite(n)) onSetSetting(f.key, Math.min(f.max, Math.max(f.min, Math.round(n))));
                      }}
                    />
                  </label>
                ))}
                <div style={{ ...dim, fontSize: 11 }}>其余 scoring 键直接改 settings.json 即生效。</div>
              </div>
            ) : null}
          </div>
          <div style={{ marginTop: 6 }}>
            <div style={dim}>年龄查询</div>
            <label style={{ display: "block", cursor: "pointer" }}>
              <input
                type="checkbox"
                checked={s.ageQueryEnabled}
                onChange={(e) => onSetSetting("ageQueryEnabled", e.target.checked)}
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
                <button key={f} type="button" style={button} onClick={() => onOpenFile(f)}>
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
  );
}
