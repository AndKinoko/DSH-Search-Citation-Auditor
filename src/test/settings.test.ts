/**
 * 设置卡片与交互报表（host 半边）测试：
 * Phase 2：schema 默认值与映射、status 负载、open-file 守卫、test-age 路由；
 * Phase 3：audit 端点（verdicts + 名单隶属）、list 端点（名单增删）、非法 body 拒绝。
 */
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough } from "node:stream";
import test from "node:test";
import { Auditor } from "../auditor/service.js";
import { AgeQueryFile } from "../auditor/ageQueryFile.js";
import { DEFAULT_SETTINGS, type Settings } from "../auditor/types.js";
import { DirectoryStore } from "../storage.js";
import {
  makeSectionSchema,
  sectionToSettings,
  settingsToSection,
  type CitationSettingsSection,
} from "../settingsSection.js";
import {
  applyListOp,
  buildAuditPayload,
  buildStatusPayload,
  isOpenableFile,
  makeCitationRoutes,
  openCommandFor,
} from "../routes.js";

function fakeRes(): { res: unknown; body(): Record<string, unknown>; status(): number } {
  let statusCode = 0;
  let payload: Record<string, unknown> = {};
  const res = {
    writeHead(code: number): unknown {
      statusCode = code;
      return res;
    },
    end(data?: Buffer): void {
      if (data !== undefined) payload = JSON.parse(data.toString("utf8")) as Record<string, unknown>;
    },
  };
  return { res, body: () => payload, status: () => statusCode };
}

function makeAuditor(dir: string, seedCode = ""): Auditor {
  const store = new DirectoryStore(dir);
  const ageFile = new AgeQueryFile(dir);
  ageFile.ensure(seedCode);
  const auditor = new Auditor(store, ageFile);
  auditor.init();
  return auditor;
}

test("section schema：空对象解析出全部默认值", () => {
  const schema = makeSectionSchema();
  const s = (schema as unknown as (input: unknown) => unknown)({}) as CitationSettingsSection;
  assert.equal(s.enabled, true);
  assert.equal(s.mode, "normal");
  assert.equal(s.blocklistEnabledNormal, true);
  assert.equal(s.whitelistEnabledNormal, true);
  assert.equal(s.ageQueryEnabled, false);
});

test("settings ↔ section 双向映射：开关各就各位，ageQuery.code 不丢", () => {
  const custom: Settings = {
    ...DEFAULT_SETTINGS,
    enabled: false,
    mode: "simple",
    blocklistEnabled: { whitelist: false, normal: false, simple: true },
    whitelistEnabled: { normal: false },
    ageQuery: { code: "/* 保留 */", enabled: true },
  };
  const section = settingsToSection(custom);
  assert.deepEqual(section, {
    enabled: false,
    mode: "simple",
    blocklistEnabledWhitelist: false,
    blocklistEnabledNormal: false,
    blocklistEnabledSimple: true,
    whitelistEnabledNormal: false,
    ageQueryEnabled: true,
  });
  const back = sectionToSettings(section, custom);
  assert.equal(back.enabled, false);
  assert.equal(back.mode, "simple");
  assert.deepEqual(back.blocklistEnabled, { whitelist: false, normal: false, simple: true });
  assert.deepEqual(back.whitelistEnabled, { normal: false });
  assert.deepEqual(back.ageQuery, { code: "/* 保留 */", enabled: true });
  assert.equal(back.onFailure, "treatAsNew");
});

test("buildStatusPayload：文件路径、名单数量、设置快照", () => {
  const dir = mkdtempSync(join(tmpdir(), "citation-auditor-test-"));
  try {
    const auditor = makeAuditor(dir, "async () => undefined");
    auditor.rules.addToWhitelist("github.com", "test");
    auditor.rules.addToBlocklist("evil.example", "test");
    const payload = buildStatusPayload(auditor, dir) as {
      ok: boolean;
      stateDir: string;
      files: Record<string, string>;
      counts: { whitelist: number; blocklist: number };
      settings: CitationSettingsSection;
      ageQueryReady: boolean;
    };
    assert.equal(payload.ok, true);
    assert.equal(payload.stateDir, dir);
    assert.equal(payload.files.whitelist, join(dir, "whitelist.json"));
    assert.equal(payload.files.ageQuery, join(dir, "ageQuery.js"));
    assert.equal(payload.counts.whitelist >= 1, true, "预写白名单至少一条");
    assert.equal(payload.counts.blocklist >= 1, true, "预写拦截名单至少一条");
    assert.equal(payload.settings.ageQueryEnabled, false);
    assert.equal(payload.ageQueryReady, true);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("open-file 守卫与平台命令", () => {
  assert.equal(isOpenableFile("whitelist"), true);
  assert.equal(isOpenableFile("ageQuery"), true);
  assert.equal(isOpenableFile("../etc/passwd"), false);
  assert.equal(isOpenableFile(42), false);
  const p = "C:\\state\\whitelist.json";
  assert.deepEqual(openCommandFor(p, "win32"), { cmd: "cmd", args: ["/c", "start", "", p] });
  assert.deepEqual(openCommandFor(p, "darwin"), { cmd: "open", args: [p] });
  assert.deepEqual(openCommandFor(p, "linux"), { cmd: "xdg-open", args: [p] });
});

test("test-age 路由：POST + 注入 fetch，wikipedia.org 当场返回日期", async () => {
  const dir = mkdtempSync(join(tmpdir(), "citation-auditor-test-"));
  try {
    const auditor = makeAuditor(dir, "(domain) => ({ creationDate: '2001-01-15T00:00:00Z' })");
    const fetchCalls: string[] = [];
    const fetchImpl = (async (url: string | URL) => {
      fetchCalls.push(String(url));
      return {
        ok: true,
        json: async () => ({ events: [{ eventAction: "registration", eventDate: "2001-01-15T00:00:00Z" }] }),
      };
    }) as unknown as typeof fetch;
    const routes = makeCitationRoutes(auditor, dir, { fetchImpl });
    assert.equal(routes.length, 6);
    assert.deepEqual(
      routes.map((r) => r.path),
      [
        "/api/citation-auditor/status",
        "/api/citation-auditor/test-age",
        "/api/citation-auditor/open-file",
        "/api/citation-auditor/audit",
        "/api/citation-auditor/list",
        "/api/citation-auditor/settings",
      ],
    );
    const testAge = routes[1]!;
    const { res, body } = fakeRes();
    await testAge.handler({ method: "POST" } as never, res as never);
    assert.equal(body().ok, true, "固定片段返回成功");
    assert.equal((body() as { creationDate?: string }).creationDate, "2001-01-15T00:00:00.000Z");

    const getStatus = routes[0]!;
    const { res: res2, body: body2 } = fakeRes();
    await getStatus.handler({ method: "GET" } as never, res2 as never);
    assert.equal(body2().ok, true);

    const openFile = routes[2]!;
    const { res: res3, body: body3 } = fakeRes();
    await openFile.handler({ method: "POST" } as never, res3 as never);
    assert.equal(body3().ok, false, "缺 body 的 open-file 请求被拒绝");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("settings 路由：POST 写设置落盘，非法字段被拒绝", async () => {
  const dir = mkdtempSync(join(tmpdir(), "citation-auditor-test-"));
  try {
    const auditor = makeAuditor(dir, "");
    const routes = makeCitationRoutes(auditor, dir);
    const settingsRoute = routes[5]!;
    assert.equal(settingsRoute.path, "/api/citation-auditor/settings");

    const fakeReq = (json: unknown): unknown => {
      const stream = new PassThrough() as PassThrough & { method: string };
      stream.method = "POST";
      stream.write(JSON.stringify(json));
      stream.end();
      return stream;
    };

    // 写 mode
    let { res, body } = fakeRes();
    await settingsRoute.handler(fakeReq({ mode: "simple" }) as never, res as never);
    const outMode = body() as { ok: boolean; settings: { mode: string } };
    assert.equal(outMode.ok, true);
    assert.equal(outMode.settings.mode, "simple", "mode 写入生效");
    assert.equal(auditor.getSettings().mode, "simple", "settings.json 真源已更新");

    // 非法字段被拒
    ({ res, body } = fakeRes());
    await settingsRoute.handler(fakeReq({ bogus: 1 }) as never, res as never);
    const outBad = body() as { ok: boolean; error?: string };
    assert.equal(outBad.ok, false, "非法字段应被拒绝");
    assert.ok(outBad.error, "带错误信息");

    // 布尔字段
    ({ res, body } = fakeRes());
    await settingsRoute.handler(fakeReq({ enabled: false }) as never, res as never);
    assert.equal(auditor.getSettings().enabled, false, "enabled 写入生效");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("buildAuditPayload：verdicts 结构化 + 名单隶属标记 + 按钮状态机事实", async () => {
  const dir = mkdtempSync(join(tmpdir(), "citation-auditor-test-"));
  try {
    const auditor = makeAuditor(dir);
    auditor.rules.addToBlocklist("blocked.example", "测试");
    const payload = (await buildAuditPayload(
      auditor,
      "来源一 https://github.com/a，来源二 https://blocked.example/x，来源三 https://random-site.xyz/。",
    )) as {
      ok: boolean;
      enabled: boolean;
      mode: string;
      blocklistEnabled: boolean;
      verdicts: Array<{
        domain: string;
        score: number;
        level: string;
        reasons: string[];
        sourceKind: string;
        inWhitelist: boolean;
        inBlocklist: boolean;
        creationDate?: string;
      }>;
    };
    assert.equal(payload.ok, true);
    assert.equal(payload.enabled, true);
    assert.equal(payload.mode, "normal");
    assert.equal(payload.blocklistEnabled, true, "normal 模式默认开拦截名单");
    assert.equal(payload.verdicts.length, 3, "三个域名全部被提取");
    const byDomain = new Map(payload.verdicts.map((v) => [v.domain, v]));

    const github = byDomain.get("github.com");
    assert.ok(github);
    assert.equal(github.inWhitelist, true, "预写白名单命中 → 按钮应显示已白名单");
    assert.equal(github.level, "trusted", "普通模式白名单免查加速默认开");

    const blocked = byDomain.get("blocked.example");
    assert.ok(blocked);
    assert.equal(blocked.inBlocklist, true, "拦截名单命中 → 按钮应显示已拦截");
    assert.equal(blocked.sourceKind, "拦截名单");
    assert.equal(blocked.level, "critical");

    const random = byDomain.get("random-site.xyz");
    assert.ok(random);
    assert.equal(random.inWhitelist, false);
    assert.equal(random.inBlocklist, false);
    assert.equal(random.sourceKind, "未能验证");
    assert.equal(random.creationDate, undefined, "ageQuery 未启用时没有创建日期");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("applyListOp：四种操作落盘并返回更新后的隶属与数量", () => {
  const dir = mkdtempSync(join(tmpdir(), "citation-auditor-test-"));
  try {
    const auditor = makeAuditor(dir);
    const beforeBlock = auditor.rules.getBlocklist().length;
    const added = applyListOp(auditor, "block", "Foo.Example.COM", "报表标记") as {
      ok: boolean;
      op: string;
      domain: string;
      inBlocklist: boolean;
      inWhitelist: boolean;
      counts: { blocklist: number };
    };
    assert.equal(added.ok, true);
    assert.equal(added.op, "block");
    assert.equal(added.domain, "foo.example.com", "域名小写归一");
    assert.equal(added.inBlocklist, true);
    assert.equal(added.counts.blocklist, beforeBlock + 1);

    const removed = applyListOp(auditor, "unblock", "foo.example.com", "") as {
      ok: boolean;
      inBlocklist: boolean;
      counts: { blocklist: number };
    };
    assert.equal(removed.ok, true);
    assert.equal(removed.inBlocklist, false, "移除后隶属解除");
    assert.equal(removed.counts.blocklist, beforeBlock);

    const white = applyListOp(auditor, "whitelist", "example.org", "") as { inWhitelist: boolean };
    assert.equal(white.inWhitelist, true);
    const unwhite = applyListOp(auditor, "unwhitelist", "example.org", "") as { inWhitelist: boolean };
    assert.equal(unwhite.inWhitelist, false);

    const empty = applyListOp(auditor, "block", "   ", "") as { ok: boolean };
    assert.equal(empty.ok, false, "空域名拒绝");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("audit/list 路由：POST JSON 体走通，非法 body 拒绝", async () => {
  const dir = mkdtempSync(join(tmpdir(), "citation-auditor-test-"));
  try {
    const auditor = makeAuditor(dir);
    const routes = makeCitationRoutes(auditor, dir);
    const auditRoute = routes[3]!;
    const listRoute = routes[4]!;

    const fakeReq = (json: unknown): unknown => {
      const stream = new PassThrough() as PassThrough & { method: string };
      stream.method = "POST"; // readJsonBody 走流接口，路由守卫只看 method
      stream.write(JSON.stringify(json));
      stream.end();
      return stream;
    };

    const { res: r1, body: b1 } = fakeRes();
    await auditRoute.handler(fakeReq({ text: "看 https://github.com/a" }) as never, r1 as never);
    const auditPayload = b1() as { ok: boolean; verdicts: unknown[] };
    assert.equal(auditPayload.ok, true);
    assert.deepEqual(auditPayload.verdicts.map((v) => (v as { domain: string }).domain), ["github.com"]);

    const { res: r2, body: b2 } = fakeRes();
    await auditRoute.handler(fakeReq({ text: 42 }) as never, r2 as never);
    assert.equal(b2().ok, false, "非字符串 text 被拒绝");

    const { res: r3, body: b3 } = fakeRes();
    await listRoute.handler(fakeReq({ op: "block", domain: "evil.example" }) as never, r3 as never);
    const listPayload = b3() as { ok: boolean; inBlocklist: boolean };
    assert.equal(listPayload.ok, true);
    assert.equal(listPayload.inBlocklist, true);

    const { res: r4, body: b4 } = fakeRes();
    await listRoute.handler(fakeReq({ op: "explode", domain: "x" }) as never, r4 as never);
    assert.equal(b4().ok, false, "非法 op 被拒绝");

    const { res: r5, body: b5 } = fakeRes();
    await listRoute.handler({ method: "GET" } as never, r5 as never);
    assert.equal(b5().ok, false, "GET 不允许");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
