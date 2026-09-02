/**
 * Citation Auditor 浏览器半边（client bundle 入口）。
 *
 * 三件事：
 *  1. 设置卡片 → settings.section list slot（模式照抄 dsh-pet）
 *  2. 交互报表行 → tool.call.toolview keyed slot（key = "citation_audit"），
 *     在会话里替换 citation_audit 的通用工具卡片（Phase 3）
 *  3. 最近回复网址悬浮窗 → 不走 slot，直接挂 document.body（Phase 4）
 *
 * 数据来源：全部走插件自有的同源 JSON 端点 /api/citation-auditor/*（status /
 * audit / list / settings / test-age / open-file）——设置、名单、年龄的读写
 * 都以 host 的 settings.json 为唯一真源，不依赖 harness 的 settings 服务
 * （其命名空间注册在当前宿主环境不可靠，实测 settings-not-exposed）。
 */
import type { ClientContext } from "@deepseek-ai/dsh-client-runtime/client";
// Type-only：拉 Context 合并（ctx.slots / ctx.settingsScope / ctx.sessions），运行时零依赖
import type {} from "@deepseek-ai/dsh-client-ui-slots";
import type {} from "@deepseek-ai/dsh-client-ui-settings/client";
import type {} from "@deepseek-ai/dsh-client-ui-conversation/client";
// Type-only：拉 SlotMap 合并（tool.call.toolview 键存在），运行时零依赖
import type {} from "@deepseek-ai/dsh-client-ui-tool/client";
import { CitationSettingsCard } from "./SettingsCard.js";
import { CitationAuditRow } from "./AuditReportCard.js";
import { mountFloatWindow } from "./FloatWindow.js";

/**
 * client 需要的宿主服务。sessions 供悬浮窗读当前会话的最近回复；
 * uiConversation 提供对话节点（ChatSnapshot）——新宿主悬浮窗的数据层。
 * 该服务经 dsh.client.inject 声明的 @deepseek-ai/dsh-client-ui-conversation 提供。
 */
export const inject = ["slots", "settingsScope", "sessions", "uiConversation"];

export function apply(ctx: ClientContext): void {
  // 悬浮窗：uiConversation 是硬依赖（对话节点所在层），随 inject 就绪。
  // 老宿主无该服务时按宿主声明版本（>=0.1.1-rc.1）本就不应挂载悬浮窗。
  try {
    mountFloatWindow(ctx);
  } catch {
    // 挂载失败可接受：设置卡片与报表不受影响
  }
  // settings.section 是 list slot：一个注册项 = 设置页导航里的一个独立页面
  ctx.slots.inject("settings.section", () => {
    try {
      const unregister = ctx.slots.register(
        {
          name: "settings.section",
          id: "citation-auditor",
          order: 200,
          label: () => "Citation Auditor",
          inject: () => ({}),
        },
        CitationSettingsCard,
      );
      return unregister;
    } catch {
      // slots 服务形态不匹配（宿主过旧）：不贡献 UI，host 工具不受影响
      return () => {};
    }
  });

  // tool.call.toolview 是 keyed slot：key = wire 工具名。注册后 citation_audit
  // 的调用在会话里渲染成交互报表（宿主过旧没有该 slot 时静默跳过，通用卡片兜底）
  ctx.slots.inject("tool.call.toolview", () => {
    try {
      const unregister = ctx.slots.register(
        {
          name: "tool.call.toolview",
          key: "citation_audit",
          inject: () => ({}),
        },
        CitationAuditRow,
      );
      return unregister;
    } catch {
      return () => {};
    }
  });
}
