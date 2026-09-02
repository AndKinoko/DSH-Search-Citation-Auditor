/**
 * 设置卡片的 host 数据面：同源 JSON 端点（/api/citation-auditor/*），模式照抄
 * dsh-pet 的 /api/pet/*（webServer 只供 client bundle，RPC 域平台注册，
 * 插件自备 API 是标准做法）。webserver 默认只听 loopback。
 *
 * 端点：
 *  - GET  status     设置快照 + 名单数量 + 各文件绝对路径
 *  - POST test-age   固定用 wikipedia.org 跑一次 ageQuery.js（设卡片的 [测试 ▸]）
 *  - POST open-file  用系统默认程序打开对应文件（[查看/编辑 ▸]）
 *  - POST audit      重跑一次审计（client 交互报表的数据源；走缓存，成本可忽略）
 *  - POST list       名单增删（client 报表按钮的写入通道，与 citation_manage 同一底层）
 *  - POST settings   设置字段写入（client 设置卡片 / 悬浮窗设置 / 报表"开启并保存"的统一通道，
 *                    直接落盘 settings.json 唯一真源，不依赖 harness 的 settings 服务）
 */
import { spawn } from "node:child_process";
import type { IncomingMessage, ServerResponse } from "node:http";
import { join } from "node:path";
import type { WebRoute } from "@deepseek-ai/dsh-host-webserver";
import type { Auditor } from "./auditor/service.js";
import { testAgeQuery } from "./auditor/ageQuery.js";
import { settingsToSection, sectionToSettings, type CitationSettingsSection } from "./settingsSection.js";

/** 浏览器侧 API 基路径。 */
export const API_PREFIX = "/api/citation-auditor";

/** 设置卡片可打开的文件（key → 状态目录里的文件名）。 */
export const OPENABLE_FILES = {
  whitelist: "whitelist.json",
  blocklist: "blocklist.json",
  settings: "settings.json",
  ageQuery: "ageQuery.js",
} as const;

export type OpenableFile = keyof typeof OPENABLE_FILES;

export function isOpenableFile(v: unknown): v is OpenableFile {
  return typeof v === "string" && v in OPENABLE_FILES;
}

/** 跨平台"用默认程序打开文件"的命令（导出以便测试）。 */
export function openCommandFor(path: string, platform: NodeJS.Platform): { cmd: string; args: string[] } {
  if (platform === "win32") return { cmd: "cmd", args: ["/c", "start", "", path] };
  if (platform === "darwin") return { cmd: "open", args: [path] };
  return { cmd: "xdg-open", args: [path] };
}

function writeJson(res: ServerResponse, status: number, value: unknown): void {
  const body = Buffer.from(JSON.stringify(value), "utf8");
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": String(body.byteLength),
    "cache-control": "no-cache",
  });
  res.end(body);
}

function readJsonBody(req: IncomingMessage): Promise<Record<string, unknown> | null> {
  return new Promise((resolvePromise, rejectPromise) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on("data", (chunk: Buffer) => {
      size += chunk.byteLength;
      if (size > 64 * 1024) {
        rejectPromise(new Error("body too large"));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => {
      const raw = Buffer.concat(chunks).toString("utf8");
      if (raw.trim() === "") {
        resolvePromise(null);
        return;
      }
      try {
        resolvePromise(JSON.parse(raw) as Record<string, unknown>);
      } catch {
        rejectPromise(new Error("invalid JSON body"));
      }
    });
    req.on("error", rejectPromise);
  });
}

/** status 端点的负载组装（导出以便测试）。 */
export function buildStatusPayload(auditor: Auditor, stateDir: string): Record<string, unknown> {
  const s = auditor.getSettings();
  const files = Object.fromEntries(
    Object.entries(OPENABLE_FILES).map(([key, file]) => [key, join(stateDir, file)]),
  );
  return {
    ok: true,
    stateDir,
    files,
    counts: {
      whitelist: auditor.rules.getWhitelist().length,
      blocklist: auditor.rules.getBlocklist().length,
    },
    settings: settingsToSection(s),
    ageQueryReady: auditor.getAgeQueryCode().trim() !== "",
  };
}

/** 名单变更操作（client 报表按钮 → host 落盘）。 */
export type ListOp = "block" | "unblock" | "whitelist" | "unwhitelist";

export function isListOp(v: unknown): v is ListOp {
  return v === "block" || v === "unblock" || v === "whitelist" || v === "unwhitelist";
}

/** audit 端点的负载组装（导出以便测试）：verdicts + 按钮状态机需要的设置事实。 */
export function buildAuditPayload(auditor: Auditor, text: string): Promise<Record<string, unknown>> {
  return auditor.audit(text).then((outcome) => {
    const s = auditor.getSettings();
    const whitelist = auditor.rules.whitelistSet();
    const { domains: blockDomains } = auditor.rules.blocklistSets();
    return {
      ok: true,
      enabled: s.enabled,
      mode: s.mode,
      blocklistEnabled: s.blocklistEnabled[s.mode],
      summary: outcome.summary ?? "",
      verdicts: outcome.result.verdicts.map((v) => ({
        domain: v.domain,
        score: v.score,
        level: v.level,
        reasons: v.reasons,
        sourceKind: v.sourceKind ?? "未能验证",
        ...(v.creationDate !== undefined ? { creationDate: v.creationDate } : {}),
        inWhitelist: whitelist.has(v.domain),
        inBlocklist: blockDomains.has(v.domain),
      })),
    };
  });
}

/** list 端点的写入执行（导出以便测试）：返回更新后的名单隶属与数量。 */
export function applyListOp(
  auditor: Auditor,
  op: ListOp,
  domain: string,
  reason: string,
): Record<string, unknown> {
  const target = domain.trim().toLowerCase();
  if (target === "") return { ok: false, error: "domain 不能为空" };
  switch (op) {
    case "block":
      auditor.rules.addToBlocklist(target, reason);
      break;
    case "whitelist":
      auditor.rules.addToWhitelist(target, reason);
      break;
    case "unblock":
      auditor.rules.removeFromList("blocklist", target);
      break;
    case "unwhitelist":
      auditor.rules.removeFromList("whitelist", target);
      break;
  }
  return {
    ok: true,
    op,
    domain: target,
    inWhitelist: auditor.rules.whitelistSet().has(target),
    inBlocklist: auditor.rules.blocklistSets().domains.has(target),
    counts: {
      whitelist: auditor.rules.getWhitelist().length,
      blocklist: auditor.rules.getBlocklist().length,
    },
  };
}

/** 组装五条路由。webServer 不可用时整个返回空数组（插件照常运行）。 */
export function makeCitationRoutes(
  auditor: Auditor,
  stateDir: string,
  opts: { fetchImpl?: typeof fetch } = {},
): WebRoute[] {
  const statusRoute: WebRoute = {
    kind: "exact",
    path: `${API_PREFIX}/status`,
    handler: (_req, res) => {
      writeJson(res, 200, buildStatusPayload(auditor, stateDir));
    },
  };

  const testAgeRoute: WebRoute = {
    kind: "exact",
    path: `${API_PREFIX}/test-age`,
    handler: (req, res) => {
      if (req.method !== "POST") {
        writeJson(res, 405, { ok: false, error: "method not allowed" });
        return;
      }
      // 固定测试域名 wikipedia.org（设计稿规则 3）；fetchImpl 可注入（测试用）。
      // 返回 promise：调用方（含测试）能等到响应写完。
      return testAgeQuery(auditor.getAgeQueryCode(), { fetchImpl: opts.fetchImpl }).then(
        (r) => {
          writeJson(
            res,
            200,
            r.ok
              ? { ok: true, creationDate: r.creationDate, domain: "wikipedia.org" }
              : { ok: false, error: r.error ?? "unknown" },
          );
        },
        (error: unknown) => {
          writeJson(res, 200, { ok: false, error: error instanceof Error ? error.message : String(error) });
        },
      );
    },
  };

  const openFileRoute: WebRoute = {
    kind: "exact",
    path: `${API_PREFIX}/open-file`,
    handler: (req, res) => {
      if (req.method !== "POST") {
        writeJson(res, 405, { ok: false, error: "method not allowed" });
        return;
      }
      return readJsonBody(req).then((body) => {
        const file = body?.["file"];
        if (!isOpenableFile(file)) {
          writeJson(res, 400, { ok: false, error: `file 必须是 ${Object.keys(OPENABLE_FILES).join("/")}` });
          return;
        }
        const path = join(stateDir, OPENABLE_FILES[file]);
        const { cmd, args } = openCommandFor(path, process.platform);
        try {
          // detached + ignore：只负责唤起默认程序，不等它退出也不接它的输出
          const child = spawn(cmd, args, { detached: true, stdio: "ignore" });
          child.unref();
          writeJson(res, 200, { ok: true, path, file });
        } catch (error) {
          writeJson(res, 500, { ok: false, error: error instanceof Error ? error.message : String(error) });
        }
      }, (error: unknown) => {
        writeJson(res, 400, { ok: false, error: error instanceof Error ? error.message : String(error) });
      });
    },
  };

  const auditRoute: WebRoute = {
    kind: "exact",
    path: `${API_PREFIX}/audit`,
    handler: (req, res) => {
      if (req.method !== "POST") {
        writeJson(res, 405, { ok: false, error: "method not allowed" });
        return;
      }
      return readJsonBody(req).then((body) => {
        const text = body?.["text"];
        if (typeof text !== "string") {
          writeJson(res, 400, { ok: false, error: "text 必须是字符串" });
          return;
        }
        // 返回内层 promise：调用方 await handler 时响应已写完（测试依赖这一点）
        return buildAuditPayload(auditor, text).then(
          (payload) => writeJson(res, 200, payload),
          (error: unknown) => {
            writeJson(res, 500, { ok: false, error: error instanceof Error ? error.message : String(error) });
          },
        );
      }, (error: unknown) => {
        writeJson(res, 400, { ok: false, error: error instanceof Error ? error.message : String(error) });
      });
    },
  };

  const listRoute: WebRoute = {
    kind: "exact",
    path: `${API_PREFIX}/list`,
    handler: (req, res) => {
      if (req.method !== "POST") {
        writeJson(res, 405, { ok: false, error: "method not allowed" });
        return;
      }
      return readJsonBody(req).then((body) => {
        const op = body?.["op"];
        const domain = body?.["domain"];
        const reason = typeof body?.["reason"] === "string" ? (body["reason"] as string) : "";
        if (!isListOp(op)) {
          writeJson(res, 400, { ok: false, error: "op 必须是 block/unblock/whitelist/unwhitelist" });
          return;
        }
        if (typeof domain !== "string") {
          writeJson(res, 400, { ok: false, error: "domain 必须是字符串" });
          return;
        }
        writeJson(res, 200, applyListOp(auditor, op, domain, reason));
      }, (error: unknown) => {
        writeJson(res, 400, { ok: false, error: error instanceof Error ? error.message : String(error) });
      });
    },
  };

  /**
   * 设置写入端点：client 设置卡片 / 悬浮窗设置视图 / 交互报表"开启并保存"都走这里，
   * 直接落盘 settings.json（插件唯一真源），不依赖 harness 的 settings 服务——
   * 该服务的命名空间注册在当前宿主环境下不可靠（settings-not-exposed）。
   * 接受 flat section 的任意子集（如 { enabled: false } 或 { mode: "simple" }）。
   */
  const settingsRoute: WebRoute = {
    kind: "exact",
    path: `${API_PREFIX}/settings`,
    handler: (req, res) => {
      if (req.method !== "POST") {
        writeJson(res, 405, { ok: false, error: "method not allowed" });
        return;
      }
      return readJsonBody(req).then(
        (body) => {
          const patch = body as Record<string, unknown> | null;
          if (patch === null || typeof patch !== "object") {
            writeJson(res, 400, { ok: false, error: "body 必须是设置对象" });
            return;
          }
          const BOOL_FIELDS: ReadonlyArray<keyof CitationSettingsSection> = [
            "enabled", "blocklistEnabledWhitelist", "blocklistEnabledNormal",
            "blocklistEnabledSimple", "whitelistEnabledNormal", "ageQueryEnabled",
          ];
          const clean: Record<string, unknown> = {};
          for (const field of BOOL_FIELDS) {
            if (typeof patch[field] === "boolean") clean[field] = patch[field];
          }
          if (patch["mode"] === "whitelist" || patch["mode"] === "normal" || patch["mode"] === "simple") {
            clean.mode = patch["mode"];
          }
          if (Object.keys(clean).length === 0) {
            writeJson(res, 400, { ok: false, error: "没有可识别的设置字段" });
            return;
          }
          const current = auditor.getSettings();
          const section = { ...settingsToSection(current), ...clean } as CitationSettingsSection;
          auditor.rules.saveSettings(sectionToSettings(section, current));
          writeJson(res, 200, { ok: true, settings: settingsToSection(auditor.getSettings()) });
        },
        (error: unknown) => {
          writeJson(res, 400, { ok: false, error: error instanceof Error ? error.message : String(error) });
        },
      );
    },
  };

  return [statusRoute, testAgeRoute, openFileRoute, auditRoute, listRoute, settingsRoute];
}
