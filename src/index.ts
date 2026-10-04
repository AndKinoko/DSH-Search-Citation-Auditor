/**
 * Cordis 插件入口（DSH 插件规范 v2.0，host-only bundle）。
 *
 * 导出 name / inject / Config / apply，向 tools 服务注册两个模型可见工具：
 *  - citation_audit：审计一段文本里的引用链接，返回结构化结果 + 纯文本报表
 *  - citation_manage：模式切换、总开关、名单增删、状态查看、年龄片段测试
 *
 * 持久化：~/.citation-auditor/ 目录下每个 key 一个 JSON 文件（whitelist / blocklist /
 * settings / cache）+ ageQuery.js 片段文件，人可直接打开编辑，改完即生效。
 * 旧版单文件 state.json 首次启动时自动拆分迁移（改名保留，不删除）。
 *
 * 设计：检测 + 报表 + 真实拦截。拦截名单不仅标记报表，还会在 tools/pre-execute
 * 阶段真正阻止模型经 web 工具访问被拦域名；名单完全归用户维护（增删即生效）。
 * 所有注册经 ctx.effect 拥有，卸载时由 Cordis 依序清理（§3.2）。
 */
import { homedir } from "node:os";
import { isAbsolute, join, resolve } from "node:path";
import Schema from "@deepseek-ai/schemastery";
import type { Context } from "@deepseek-ai/cordis";
import type { ContentBlock } from "@deepseek-ai/dsh-llm";
import { defineTool, type PreToolDecision, type ToolExecution, type PostToolDecision } from "@deepseek-ai/dsh-tools";
import { Auditor } from "./auditor/service.js";
import { testAgeQuery } from "./auditor/ageQuery.js";
import { AgeQueryFile } from "./auditor/ageQueryFile.js";
import type { Mode } from "./auditor/types.js";
import { DirectoryStore, migrateLegacyState } from "./storage.js";
import { blockedToolDecision } from "./webBlock.js";
import { guardFetchContent } from "./injectionBlock.js";
import { DEFAULT_INJECTION } from "./auditor/injection/types.js";
import { installSettingsCard } from "./settingsSection.js";
import { makeCitationRoutes } from "./routes.js";

/** Cordis 插件标识：非 scope 包名，必须等于 package.json 的 name（规范 §2.1.7）。 */
export const name = "dsh-citation-auditor";

/** 硬依赖：工具注册表。缺失时插件保持 PENDING，直到服务就绪。 */
export const inject = ["tools"];

export interface AuditorConfig {
  /** 存储目录。留空用默认 ~/.citation-auditor；相对路径按家目录解析。 */
  statePath?: string;
}

export const Config: Schema<AuditorConfig> = Schema.object({
  statePath: Schema.string().default("").description("存储目录；留空用 ~/.citation-auditor"),
});

/** 解析存储目录：显式配置优先；相对路径按家目录解析，不依赖 process.cwd()（规范 §3.5.6）。 */
export function resolveStatePath(statePath: string | undefined): string {
  const raw = (statePath ?? "").trim();
  if (raw === "") return join(homedir(), ".citation-auditor");
  return isAbsolute(raw) ? raw : resolve(homedir(), raw);
}

export function apply(ctx: Context, config: AuditorConfig): void {
  const dir = resolveStatePath(config.statePath);
  const legacyCode = migrateLegacyState(dir); // 旧单文件 state.json → 目录布局
  const store = new DirectoryStore(dir);
  const ageQueryFile = new AgeQueryFile(dir);
  ageQueryFile.ensure(legacyCode); // 首次生成 ageQuery.js（迁移出的旧代码优先）
  const auditor = new Auditor(store, ageQueryFile);
  auditor.init();

  const auditTool = defineTool({
    name: "citation_audit",
    description:
      "审计一段文本里的引用链接来源可信度。输入完整文本（如 AI 回复），" +
      "返回按威胁度排序的域名清单与纯文本报表。只检测不拦截；结果仅供参考，处置权在用户。",
    parameters: {
      text: { type: "string", required: true, description: "要审计的完整文本" },
    },
    output: {
      schema: {
        type: "object",
        additionalProperties: false,
        properties: {
          summary: { type: "string", required: true, description: "一行摘要；无域名时为空串" },
          report: { type: "string", required: true, description: "纯文本报表" },
          domainCount: { type: "integer", required: true, description: "发现的域名数量" },
          verdicts: {
            type: "array",
            required: true,
            description: "结构化判决清单（按威胁度降序；client 交互报表数据源）",
            items: {
              type: "object",
              additionalProperties: false,
              properties: {
                domain: { type: "string", required: true, description: "注册域（PSL eTLD+1）" },
                score: { type: "integer", required: true, description: "威胁分 0-100" },
                level: {
                  type: "string",
                  required: true,
                  enum: ["trusted", "suspicious", "warning", "critical"],
                  description: "威胁等级",
                },
                reasons: { type: "array", required: true, items: { type: "string" }, description: "评分理由" },
                sourceKind: {
                  type: "string",
                  required: true,
                  enum: ["api_query", "cache", "whitelist", "blocklist", "unverifiable"],
                  description: "来源类型",
                },
                action: {
                  type: "string",
                  required: true,
                  enum: ["allow", "ask", "deny"],
                  description: "命中拦截名单时的处置动作（allow=仅提醒，ask=需确认，deny=直接拦截）",
                },
                creationDate: { type: "string", description: "域名创建日期（ISO）；未能验证时缺省" },
              },
            },
          },
        },
      },
      render: (_args, value) => [{ type: "text", text: value.report }],
    },
    timeoutMs: 30_000,
    isConcurrencySafe: () => false,
    async execute(args) {
      const outcome = await auditor.audit(args.text);
      return {
        summary: outcome.summary ?? "",
        report: outcome.report,
        domainCount: outcome.result.domains.length,
        verdicts: outcome.result.verdicts.map((v) => ({
          domain: v.domain,
          score: v.score,
          level: v.level,
          reasons: v.reasons,
          sourceKind: v.sourceKind ?? "unverifiable",
          action: v.action ?? "allow",
          ...(v.creationDate !== undefined ? { creationDate: v.creationDate } : {}),
        })),
      };
    },
  });

  const manageTool = defineTool({
    name: "citation_manage",
    description:
      "管理引用审计器：查看状态、启用/休眠插件、切换模式（whitelist/normal/simple）、增删白名单与拦截名单、" +
      "切换拦截策略（allow=仅提醒/ask=需确认/deny=直接拦截）、开关网页注入防护、测试年龄查询片段。" +
      "所有名单数据落盘且归用户所有。",
    parameters: {
      op: {
        type: "string",
        required: true,
        enum: ["status", "enabled", "mode", "block", "whitelist", "remove", "policy", "injection", "testAgeQuery"],
        description:
          "status=查看状态；enabled=启用/休眠插件；mode=切换模式；block=加入拦截名单；whitelist=加入白名单；remove=从名单移除；policy=切换拦截策略；injection=开关网页注入防护；testAgeQuery=用 wikipedia.org 测试年龄片段",
      },
      value: { type: "boolean", description: "op=enabled 时的目标状态（true=启用，false=休眠）" },
      mode: { type: "string", enum: ["whitelist", "normal", "simple"], description: "op=mode 时的目标模式" },
      domain: { type: "string", description: "op=block/whitelist/remove 时的域名（TLD 用 .xyz 形式）" },
      reason: { type: "string", description: "标记理由，可省略" },
      action: { type: "string", enum: ["allow", "ask", "deny"], description: "op=policy 时的目标策略（allow=仅提醒，ask=需确认，deny=直接拦截）" },
    },
    output: {
      schema: {
        type: "object",
        additionalProperties: false,
        properties: {
          result: { type: "string", required: true, description: "操作结果的人可读文本" },
        },
      },
      render: (_args, value) => [{ type: "text", text: value.result }],
    },
    isConcurrencySafe: () => false,
    async execute(args) {
      switch (args.op) {
        case "status": {
          const s = auditor.status;
          const policyLabel = s.enforcement === "deny" ? "直接拦截" : s.enforcement === "ask" ? "需确认" : "仅提醒";
          return {
            result:
              `插件: ${s.enabled ? "启用" : "休眠（所有检测关闭）"}\n模式: ${s.mode}\n` +
              `拦截名单开关(当前模式): ${s.blocklistEnabled ? "开" : "关"}\n` +
              `拦截策略: ${policyLabel}(${s.enforcement})\n` +
              `白名单: ${s.whitelistCount} 条\n拦截名单: ${s.blocklistCount} 条\n` +
              `年龄查询: ${s.ageQueryEnabled ? "启用" : "停用"}\n` +
              `网页注入防护: ${s.injectionEnabled ? "启用（仅提示）" : "关闭"}`,
          };
        }
        case "enabled": {
          if (typeof args.value !== "boolean") return { result: "缺少 value 参数（true=启用，false=休眠）" };
          const s = auditor.setEnabled(args.value);
          return { result: s.enabled ? "插件已启用" : "插件已休眠（audit 将返回空报表）" };
        }
        case "mode": {
          if (!isMode(args.mode)) return { result: `缺少或非法的 mode 参数: ${String(args.mode)}` };
          const s = auditor.setMode(args.mode);
          return { result: `已切换模式: ${s.mode}` };
        }
        case "block":
        case "whitelist": {
          const domain = (args.domain ?? "").trim();
          if (!domain) return { result: "缺少 domain 参数" };
          const list =
            args.op === "block"
              ? auditor.rules.addToBlocklist(domain, args.reason ?? "")
              : auditor.rules.addToWhitelist(domain, args.reason ?? "");
          if (list === null) return { result: "域名格式非法（空字符串或缺少点号）" };
          return { result: `${args.op === "block" ? "拦截名单" : "白名单"}现有 ${list.length} 条，含 ${domain}` };
        }
        case "remove": {
          const domain = (args.domain ?? "").trim();
          if (!domain) return { result: "缺少 domain 参数" };
          const okWhite = auditor.rules.removeFromList("whitelist", domain);
          const okBlock = auditor.rules.removeFromList("blocklist", domain);
          return { result: okWhite || okBlock ? `已移除 ${domain}` : `名单中没有 ${domain}` };
        }
        case "policy": {
          if (args.action !== "allow" && args.action !== "ask" && args.action !== "deny") {
            return { result: `缺少或非法的 action 参数: ${String(args.action)}（allow/ask/deny）` };
          }
          const s = auditor.getSettings();
          auditor.rules.saveSettings({ ...s, enforcement: { ...s.enforcement, blocklist: args.action } });
          return { result: `拦截策略已切换: ${args.action}` };
        }
        case "injection": {
          const s = auditor.getSettings();
          const cur = s.injection ?? DEFAULT_INJECTION;
          if (typeof args.value === "boolean") {
            auditor.rules.saveSettings({ ...s, injection: { ...cur, enabled: args.value } });
            return {
              result: args.value
                ? "网页注入防护已启用（web_fetch 正文命中注入时在正文前插入警示块，正文不改）"
                : "网页注入防护已关闭（web_fetch 正文不再检测）",
            };
          }
          const f = cur.fuzzy === true;
          return {
            result:
              `网页注入防护: ${cur.enabled ? "启用（仅提示）" : "关闭"}\n` +
              `typo 模糊匹配: ${f ? "开" : "关（默认）"}\n` +
              `扫描上限: ${cur.scanMaxBytes} 字节\n` +
              "用法: op=injection + value=true/false 开关防护",
          };
        }
        case "testAgeQuery": {
          const code = auditor.getAgeQueryCode(); // 实时读 ageQuery.js
          const r = await testAgeQuery(code);
          return {
            result: r.ok
              ? `测试通过：wikipedia.org 创建于 ${r.creationDate}`
              : `测试失败：${r.error ?? "unknown"}`,
          };
        }
      }
    },
  });

  // 注册经 ctx.effect 拥有：插件卸载时由 Cordis 依序反注册（规范 §3.2.1）
  ctx.effect(() => ctx.tools.register(auditTool), "tools.register citation_audit");
  ctx.effect(() => ctx.tools.register(manageTool), "tools.register citation_manage");

  // 真实拦截：tools/pre-execute 阶段检查 web 工具（web_search / web_fetch 等）
  // 参数里的域名，命中拦截名单即按策略处置（deny=直接拦截，ask=需确认，allow=仅提醒放行）。
  ctx.on("tools/pre-execute", async (exec: ToolExecution, next: () => Promise<PreToolDecision>): Promise<PreToolDecision> => {
    try {
      if (!auditor.getSettings().enabled) return next(); // 插件休眠时不拦
      const decision = blockedToolDecision(auditor, exec.name, exec.arguments);
      return decision ?? next();
    } catch (err) {
      // 拦截器自身出错绝不能升级成"拒绝调用"：那是替用户做决定，且故障表现会伪装成
      // 策略生效。降级为放行并留痕。
      logWarn(ctx, `citation-auditor: pre-execute 检查异常，已放行 — ${errText(err)}`);
      return next();
    }
  });

  // 响应侧注入防护：tools/post-execute 阶段检查 web_fetch 返回的正文，命中注入
  // 时只在正文**前面插入**一段警示块（正文一字不改），由用户自行判断是否中断。
  // 插件总开关关闭时整体旁路。
  ctx.on(
    "tools/post-execute",
    async (
      exec: ToolExecution,
      result: { isError: boolean; content: ContentBlock[] },
      next: () => Promise<PostToolDecision>,
    ): Promise<PostToolDecision> => {
      // 插件休眠不处理；工具失败时的 content 是渲染好的错误文案，没有注入面
      if (!auditor.getSettings().enabled || result.isError) return next();
      // dsh-tools 把本监听器包在 execute 的外层 try/catch 里（"a throwing listener
      // → isError"），所以这里的任何抛出都会把整个 web_fetch 结果变成工具错误，
      // 用户拿到的是报错而不是页面。防御性扫描器只能降级成"没有告警"。
      try {
        // 先把链条跑完再替换内容。cordis 明确规定「不调用 next() 的监听器会否决整条
        // 链，包括内建行为」（events.d.ts:160-162）；原实现在命中路径直接 return，
        // 于是恰恰在最需要告警的那条对抗性内容路径上，宿主里其它所有 post-execute
        // 监听器都被跳过——纯顺序依赖，谁先注册谁说了算。
        const downstream = await next();
        if (downstream.kind !== "accept") return downstream; // 下游已否决，勿覆盖
        const upstream = downstream.content ?? result.content;
        const guarded = guardFetchContent(auditor, exec.name, exec.arguments, upstream);
        if (!guarded.changed) return downstream;
        return { kind: "accept", content: guarded.content };
      } catch (err) {
        logWarn(ctx, `citation-auditor: 注入检测异常，本次不加告警 — ${errText(err)}`);
        return next();
      }
    },
  );

  // 设置命名空间的 host 注册：settings 服务存在时登记存在性（auto:false，因本插件
  // 自带设置页）。client 各界面统一走自有 /settings 端点落盘 settings.json，
  // SettingsForms 不接管数据真源，故这里无需回写回调。
  installSettingsCard(ctx);

  // client 卡片的数据端点（status / test-age / open-file）。webServer 是可选
  // 服务：纯 CLI 宿主没有它，插件其余功能不受影响。
  ctx.inject(["webServer"], (wctx) => {
    wctx.effect(() => {
      // 逐条注册并保留已成功的 disposer：WebServer.register 对重复 (kind,path)
      // 会抛错，原来的 .map 一旦中途抛出，前面 1..n-1 条已注册的路由既没有
      // disposer 也已经挂在 webServer 上，插件卸载后仍然响应并对着一个已死的
      // Auditor 服务请求。
      const routes = makeCitationRoutes(auditor, dir);
      const disposers: (() => void)[] = [];
      try {
        for (const route of routes) disposers.push(wctx.webServer.register(route));
      } catch (err) {
        for (const dispose of disposers.reverse()) {
          try {
            dispose();
          } catch {
            /* 单条回滚失败不应阻断其余回滚 */
          }
        }
        throw err;
      }
      return () => {
        for (const dispose of disposers.reverse()) {
          try {
            dispose();
          } catch {
            /* 卸载期尽力而为 */
          }
        }
      };
    }, "webServer.register citation-auditor routes");
  });
}

/** 统一的可诊断告警出口：cordis 的 logger 不在必需上下文里，拿不到就退回 stderr。 */
function logWarn(ctx: unknown, message: string): void {
  const logger = (ctx as { logger?: { warn?: (m: string) => void } })?.logger;
  if (typeof logger?.warn === "function") {
    logger.warn(message);
    return;
  }
  try {
    console.warn(message);
  } catch {
    /* 日志本身失败不应影响调用方 */
  }
}

function errText(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

function isMode(v: unknown): v is Mode {
  return v === "whitelist" || v === "normal" || v === "simple";
}
