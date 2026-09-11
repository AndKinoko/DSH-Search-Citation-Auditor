/**
 * headless 一致性测试（node:test）。
 * 覆盖：scanner / scorer 三模式与名单优先级 / report / rules 持久化 /
 * JsonFileStore 原子写与跨实例恢复 / ageQuery 编译与超时 / 插件包名一致性。
 * 纯 Node 运行，不依赖 dsh 宿主。
 */
import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync, rmSync, existsSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { scan, extractDomain, analyzeUrl, scanDetailed, aggregateDomainSignals } from "../auditor/scanner.js";
import { classify, sortByThreat, levelFromScore } from "../auditor/scorer.js";
import { renderReport, renderSummaryLine } from "../auditor/report.js";
import { RuleStore } from "../auditor/rules.js";
import { WhoIsCache } from "../auditor/cache.js";
import { queryAge, testAgeQuery, makeAgeResolver } from "../auditor/ageQuery.js";
import { AgeQueryFile } from "../auditor/ageQueryFile.js";
import { Auditor } from "../auditor/service.js";
import { DEFAULT_SETTINGS, type Mode, type Settings } from "../auditor/types.js";
import { DirectoryStore, JsonFileStore, migrateLegacyState, type KeyValueStore } from "../storage.js";
import { name as pluginName, resolveStatePath } from "../index.js";

function tempStore(): { store: KeyValueStore; file: string; cleanup: () => void } {
  const dir = mkdtempSync(join(tmpdir(), "citation-auditor-test-"));
  const file = join(dir, "state.json");
  return { store: new JsonFileStore(file), file, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

function settings(overrides: Partial<Settings> = {}): Settings {
  return {
    ...DEFAULT_SETTINGS,
    ...overrides,
    blocklistEnabled: { ...DEFAULT_SETTINGS.blocklistEnabled, ...(overrides.blocklistEnabled ?? {}) },
    ageQuery: { ...DEFAULT_SETTINGS.ageQuery, ...(overrides.ageQuery ?? {}) },
    enforcement: overrides.enforcement,
    scoring: overrides.scoring,
  };
}

const baseInput = (over: Partial<Parameters<typeof classify>[0]>) =>
  ({
    domain: "example.com",
    mode: "normal" as Mode,
    settings: settings(),
    blocklist: new Set<string>(),
    blockedTlds: new Set<string>(),
    whitelist: new Set<string>(),
    ...over,
  }) as Parameters<typeof classify>[0];

// ---------- scanner ----------

test("scanner：提取 URL 与注册域，忽略非 http(s) 与重复", () => {
  const { urls, domains } = scan(
    "看 https://www.wikipedia.org/wiki/X 和 https://en.wikipedia.org，再看 ftp://x.com 和 https://bad.site。完。",
  );
  assert.ok(urls.includes("https://www.wikipedia.org/wiki/X"));
  assert.ok(urls.includes("https://bad.site"));
  assert.ok(!urls.some((u) => u.startsWith("ftp://")));
  assert.deepEqual(domains, ["wikipedia.org", "bad.site"], "en. 子域按 eTLD+1 归并，预写白名单能命中");
});

test("scanner：extractDomain 按 PSL eTLD+1 解析", () => {
  assert.equal(extractDomain("https://example.co.uk/a"), "example.co.uk", "双段 TLD 不被截成 co.uk");
  assert.equal(extractDomain("https://www.wikipedia.org"), "wikipedia.org");
  assert.equal(extractDomain("https://en.wikipedia.org"), "wikipedia.org", "合法子域归并到注册域");
  assert.equal(extractDomain("https://a.b.c.example.com"), "example.com");
  assert.equal(extractDomain("https://localhost/x"), null, "单标签主机不当域名");
  assert.equal(extractDomain("not a url"), null);
});

test("scanner：全角标点不残留在 URL 尾部", () => {
  const { urls } = scan("来源是 https://example.com/a。没了，再看 https://example.com/b？");
  assert.ok(urls.includes("https://example.com/a"), `实际: ${urls.join(" | ")}`);
  assert.ok(urls.includes("https://example.com/b"));
  assert.ok(!urls.some((u) => /[，。；：！？、】》]$/.test(u)));
});

// ---------- v0.3 URL 结构信号 ----------

test("scanner：analyzeUrl 识别 IP/短链/追踪参数/深路径/长查询/非标准端口", () => {
  const ip = analyzeUrl("http://192.168.1.1/admin");
  assert.ok(ip?.isIp, "IPv4 直连应标记");

  const short = analyzeUrl("https://bit.ly/abc123?utm_source=x");
  assert.equal(short?.isShortener, true, "短链域名应标记");
  assert.equal(short?.hasTracking, true, "utm_ 参数应标记");

  const deep = analyzeUrl("https://example.com/a/b/c/d/e");
  assert.equal(deep?.deepPath, true, "≥4 段路径应标记");
  assert.equal(deep?.pathDepth, 5);

  const shallow = analyzeUrl("https://example.com/a");
  assert.equal(shallow?.deepPath, false);
  assert.equal(shallow?.hasTracking, false);
  assert.equal(shallow?.isShortener, false);

  const longQuery = analyzeUrl(`https://example.com/s?${"q=1&".repeat(40)}`);
  assert.equal(longQuery?.longQuery, true, "超长查询串应标记");

  const port = analyzeUrl("https://example.com:8443/x");
  assert.equal(port?.nonStandardPort, true, "非标准端口应标记");
  const stdPort = analyzeUrl("https://example.com:443/x");
  assert.equal(stdPort?.nonStandardPort, false, "标准端口不标记");

  const atPath = analyzeUrl("https://example.com/@user");
  assert.equal(atPath?.hasUserinfo, false, "路径里的 @ 不算 userinfo");

  assert.equal(analyzeUrl("not a url"), null);
});

test("scanner：userinfo 混淆 URL 完整提取并归属真实主机", () => {
  const { urls, domains, details } = scanDetailed("小心 https://trusted.com@evil.example/login 看清楚");
  assert.ok(urls.some((u) => u.includes("trusted.com@evil.example")), `实际: ${urls.join(" | ")}`);
  assert.ok(domains.includes("evil.example"), "应归属 @ 后的真实主机");
  assert.ok(!domains.includes("trusted.com"), "不得误判为 @ 前的伪装主机");
  const agg = aggregateDomainSignals(details, "evil.example");
  assert.equal(agg.hasUserinfo, true);

  const { domains: d2 } = scanDetailed("登录 https://user:pass@example.com/ 继续");
  assert.ok(d2.includes("example.com"));
});

test("scanner：scanDetailed 聚合域级信号（同域多 URL 不叠加）", () => {
  const { urls, domains, details } = scanDetailed(
    "看 https://bit.ly/a 和 https://example.com/x?utm_source=n 再看 https://example.com/y",
  );
  assert.ok(urls.length >= 3);
  assert.ok(domains.includes("bit.ly"));
  assert.ok(domains.includes("example.com"));
  const aggShort = aggregateDomainSignals(details, "bit.ly");
  assert.equal(aggShort.hasShortener, true);
  const aggEx = aggregateDomainSignals(details, "example.com");
  assert.equal(aggEx.hasTracking, true, "同域任一 URL 命中即聚合");
  assert.equal(aggEx.hasShortener, undefined);
});

test("scorer：URL 结构信号各自加分一次", () => {
  const v = classify(
    baseInput({
      domain: "example.com",
      creationDate: "2010-01-01T00:00:00Z",
      urlSignals: { hasIp: true, hasShortener: true, hasTracking: true },
    }),
  );
  // 2010 老域名无年龄加分、无 TLD 加分：25(IP)+15(短链)+5(追踪)=45 → warning
  assert.equal(v.score, 45);
  assert.equal(v.level, "warning");
  assert.ok(v.reasons.some((r) => r.includes("IP 直连")));
  assert.ok(v.reasons.some((r) => r.includes("短链")));
  assert.ok(v.reasons.some((r) => r.includes("追踪")));

  const clean = classify(baseInput({ domain: "example.com", creationDate: "2010-01-01T00:00:00Z" }));
  assert.equal(clean.score, 0, "无 URL 信号的老域名保持 0 分");
});

test("scorer：URL 信号权重可配（settings.scoring 覆盖）", () => {
  const v = classify(
    baseInput({
      domain: "example.com",
      creationDate: "2010-01-01T00:00:00Z",
      settings: settings({ scoring: { urlIpBonus: 5 } }),
      urlSignals: { hasIp: true },
    }),
  );
  assert.equal(v.score, 5);
});

test("Auditor：命中拦截名单的 verdict 自带 action（默认 deny）", async () => {
  const dir = mkdtempSync(join(tmpdir(), "citation-auditor-test-"));
  try {
    const store = new DirectoryStore(dir);
    const ageFile = new AgeQueryFile(dir);
    ageFile.ensure();
    const auditor = new Auditor(store, ageFile);
    auditor.init();
    auditor.rules.addToBlocklist("evil.example", "测试");
    const out = await auditor.audit("看 https://evil.example/x 和 https://github.com/y");
    const byDomain = new Map(out.result.verdicts.map((v) => [v.domain, v]));
    assert.equal(byDomain.get("evil.example")?.action, "deny");
    assert.equal(byDomain.get("github.com")?.action, "allow");
    assert.ok(out.report.includes("直接拦截"), "报表页脚展示当前策略");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ---------- scorer ----------

test("scorer：白名单模式——名单内绿，名单外全红", () => {
  const inList = classify(baseInput({ mode: "whitelist", whitelist: new Set(["wikipedia.org"]), domain: "wikipedia.org" }));
  const outList = classify(baseInput({ mode: "whitelist", whitelist: new Set(["wikipedia.org"]), domain: "random.site" }));
  assert.equal(inList.level, "trusted");
  assert.equal(outList.level, "critical");
});

test("scorer：简单模式——2023 前可信，之后与查不到均标红", () => {
  const pre = classify(baseInput({ mode: "simple", creationDate: "2015-03-01T00:00:00Z" }));
  const post = classify(baseInput({ mode: "simple", creationDate: "2025-06-01T00:00:00Z" }));
  const missing = classify(baseInput({ mode: "simple" }));
  assert.equal(pre.level, "trusted");
  assert.equal(post.level, "critical");
  assert.equal(missing.judgedBy, "unverifiable");
  assert.equal(missing.level, "critical");
});

test("scorer：普通模式多信号评分", () => {
  const v = classify(baseInput({ creationDate: "2025-01-01T00:00:00Z" }));
  assert.equal(v.judgedBy, "score_engine");
  assert.ok(v.score >= 50, "2023 年后注册至少 50 分");
  assert.ok(v.reasons.some((r) => r.includes("2023 年后")));
});

test("scorer：ageQuery 未启用时未验证年龄只记可疑（+20），启用后才按新域名（+50）", () => {
  // 默认配置：ageQuery.enabled=false → 普通域名最低 20 分，报表不再满屏黄
  const disabled = classify(baseInput({}));
  assert.equal(disabled.score, 20);
  assert.equal(disabled.level, "suspicious");
  assert.ok(disabled.reasons.some((r) => r.includes("年龄查询未启用")));

  const enabledMissing = classify(baseInput({ settings: settings({ ageQuery: { code: "(d)=>({})", enabled: true } }) }));
  assert.equal(enabledMissing.score, 50);
  assert.ok(enabledMissing.reasons.some((r) => r.includes("查不到年龄")));
});

test("scorer：whitelistEnabled.normal=false 时普通模式不再白名单免查", () => {
  const off = classify(
    baseInput({ whitelist: new Set(["example.com"]), settings: settings({ whitelistEnabled: { normal: false } }) }),
  );
  assert.notEqual(off.level, "trusted", "开关关闭后走正常评分");
  const on = classify(baseInput({ whitelist: new Set(["example.com"]) }));
  assert.equal(on.level, "trusted", "默认开：白名单免查");
});

test("scorer：查询失败（ageUnavailable=failed）与未启用同级降权", () => {
  const v = classify(
    baseInput({ ageUnavailable: "failed", settings: settings({ ageQuery: { code: "(d)=>({})", enabled: true } }) }),
  );
  assert.equal(v.score, 20);
  assert.equal(v.level, "suspicious");
  assert.ok(v.reasons.some((r) => r.includes("年龄查询失败")));
});

test("scorer：拦截名单优先于一切，且受每模式开关控制", () => {
  const hit = classify(baseInput({ domain: "evil.com", blocklist: new Set(["evil.com"]) }));
  assert.equal(hit.judgedBy, "blocklist");
  assert.equal(hit.level, "critical");

  // 关掉当前模式的拦截名单开关 → 不再命中，走主逻辑
  const off = classify(
    baseInput({ domain: "evil.com", blocklist: new Set(["evil.com"]), settings: settings({ blocklistEnabled: { whitelist: true, normal: false, simple: true } }) }),
  );
  assert.notEqual(off.judgedBy, "blocklist");
});

test("scorer：TLD 拦截（.xyz）", () => {
  const v = classify(baseInput({ domain: "spam.xyz", blockedTlds: new Set([".xyz"]), creationDate: "2010-01-01T00:00:00Z" }));
  assert.ok(v.score >= 40);
  assert.ok(v.reasons.some((r) => r.includes("TLD")));
});

test("scorer：TLD 拦截同样受每模式开关控制", () => {
  // 开：命中 TLD 名单加分
  const on = classify(baseInput({ domain: "spam.xyz", blockedTlds: new Set([".xyz"]), creationDate: "2010-01-01T00:00:00Z" }));
  assert.ok(on.reasons.some((r) => r.includes("TLD")));

  // 普通模式开关关：TLD 名单条目不再参与，走其他信号（本例只有年龄，2010 老域名 → 0 分可信）
  // 注意：spam.xyz 的 .xyz TLD 在高风险列表中，会额外加 tldTrustBonus（默认 10 分）
  const off = classify(
    baseInput({
      domain: "spam.xyz",
      blockedTlds: new Set([".xyz"]),
      creationDate: "2010-01-01T00:00:00Z",
      settings: settings({ blocklistEnabled: { whitelist: true, normal: false, simple: true } }),
    }),
  );
  assert.ok(!off.reasons.some((r) => r.includes("TLD 在拦截名单")), "关闭开关后不再出现 TLD 拦截理由");
  assert.equal(off.judgedBy, "score_engine");
  // .xyz 是高风险 TLD，会加 tldTrustBonus（默认 10 分），所以分数不是 0
  assert.equal(off.score, 10, "TLD 拦截名单关闭后只保留 TLD 可信度评分");
});

test("scorer：排序与分级", () => {
  const sorted = sortByThreat([
    classify(baseInput({ domain: "a.com", creationDate: "2010-01-01T00:00:00Z" })),
    classify(baseInput({ domain: "b.com", creationDate: "2025-01-01T00:00:00Z" })),
  ]);
  assert.ok(sorted[0]!.score >= sorted[1]!.score);
  assert.equal(levelFromScore(70), "critical");
  assert.equal(levelFromScore(69), "warning");
  assert.equal(levelFromScore(40), "warning");
  assert.equal(levelFromScore(39), "suspicious");
  assert.equal(levelFromScore(19), "trusted");
});

// ---------- report ----------

test("report：纯文本报表按威胁度降序，无域名时摘要为空", () => {
  const verdicts = [
    classify(baseInput({ domain: "b.com", creationDate: "2025-01-01T00:00:00Z" })),
    classify(baseInput({ domain: "a.com", creationDate: "2010-01-01T00:00:00Z" })),
  ];
  const report = renderReport(sortByThreat(verdicts));
  assert.ok(report.includes("b.com"));
  assert.ok(report.indexOf("b.com") < report.indexOf("a.com"));
  assert.ok(renderSummaryLine(sortByThreat(verdicts))!.length > 0);
  assert.equal(renderSummaryLine([]), null);
  assert.ok(renderReport([]).length > 0, "空报表仍渲染表头");
});

test("report：来源块无死按钮，页脚为纯提示文字", () => {
  const report = renderReport(sortByThreat([classify(baseInput({}))]));
  assert.ok(!report.includes("[➕ 加入拦截名单]"), "死按钮文本必须移除");
  assert.ok(report.includes("纯提示文字"));
  assert.ok(report.includes("citation_manage"), "提示应指向真正的名单操作工具");
});

// ---------- rules + JsonFileStore ----------

test("rules：首次预写幂等，增删改查落盘", () => {
  const { store, file, cleanup } = tempStore();
  try {
    const rules = new RuleStore(store);
    rules.ensureSeeded();
    const seedCount = rules.getWhitelist().length;
    rules.ensureSeeded();
    assert.equal(rules.getWhitelist().length, seedCount, "重复 init 不重复预写");

    rules.addToWhitelist("test.example", "测试");
    assert.ok(rules.whitelistSet().has("test.example"));

    // 新实例从同一文件恢复
    const rules2 = new RuleStore(new JsonFileStore(file));
    assert.ok(rules2.whitelistSet().has("test.example"));

    assert.equal(rules2.removeFromList("whitelist", "test.example"), true);
    assert.ok(!rules2.whitelistSet().has("test.example"));
    assert.equal(rules2.removeFromList("whitelist", "not-in-list.example"), false, "名单中没有时如实返回 false");

    const s = rules.getSettings();
    s.mode = "simple";
    rules.saveSettings(s);
    assert.equal(new RuleStore(new JsonFileStore(file)).getSettings().mode, "simple");
  } finally {
    cleanup();
  }
});

test("rules：blocklistSets 区分域名与 TLD", () => {
  const { store, cleanup } = tempStore();
  try {
    const rules = new RuleStore(store);
    rules.addToBlocklist("evil.com", "");
    rules.addToBlocklist(".top", "");
    const sets = rules.blocklistSets();
    assert.ok(sets.domains.has("evil.com"));
    assert.ok(sets.tlds.has(".top"));
    assert.ok(!sets.domains.has(".top"));
  } finally {
    cleanup();
  }
});

test("storage：损坏文件先备份为 .corrupt-* 再视为空，seed 不会覆盖用户数据", () => {
  const dir = mkdtempSync(join(tmpdir(), "citation-auditor-test-"));
  const file = join(dir, "state.json");
  try {
    const s1 = new JsonFileStore(file);
    s1.setItem("k", JSON.stringify({ a: 1 }));
    s1.setItem("k2", "v2");
    const leftovers = readdirSync(dir).filter((f) => f.endsWith(".tmp"));
    assert.equal(leftovers.length, 0, "flush 后不应残留 .tmp");

    const parsed = JSON.parse(readFileSync(file, "utf8")) as Record<string, string>;
    assert.equal(parsed["k2"], "v2");

    // 损坏 → 原件备份为 *.corrupt-<ts>，再视为空存储
    const bad = join(dir, "bad.json");
    writeFileSync(bad, "{ torn tail", "utf8");
    const s2 = new JsonFileStore(bad);
    assert.equal(s2.getItem("k"), undefined);
    const backups = readdirSync(dir).filter((f) => f.includes(".corrupt-"));
    assert.equal(backups.length, 1, "损坏原件必须留备份");
    assert.equal(readFileSync(join(dir, backups[0]!), "utf8"), "{ torn tail", "备份内容是损坏前的原件");

    // 之后照常写入（等价于 seed 场景），备份仍在，用户数据没有丢
    s2.setItem("k", "ok");
    assert.equal(new JsonFileStore(bad).getItem("k"), "ok");
    assert.equal(readdirSync(dir).filter((f) => f.includes(".corrupt-")).length, 1);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ---------- DirectoryStore（Phase 1：按 key 拆文件 + mtime 热重载） ----------

test("DirectoryStore：每 key 独立文件，外部编辑保存即生效（mtime 热重载）", () => {
  const dir = mkdtempSync(join(tmpdir(), "citation-auditor-test-"));
  try {
    const store = new DirectoryStore(dir);
    store.setItem("whitelist", JSON.stringify([{ domain: "a.com" }]));
    const file = join(dir, "whitelist.json");
    assert.ok(existsSync(file), "key 映射为 <dir>/whitelist.json");
    assert.ok(existsSync(join(dir, "blocklist.json")) === false, "未写的 key 不产生文件");

    // 模拟用户直接编辑文件（绕过 store）
    writeFileSync(file, JSON.stringify([{ domain: "b.com" }]), "utf8");
    assert.equal(store.getItem("whitelist"), JSON.stringify([{ domain: "b.com" }]), "外部编辑无需重启即生效");

    // 损坏单个 key：备份 + 视为空，其他 key 不受影响
    store.setItem("blocklist", JSON.stringify([{ domain: "evil.com" }]));
    writeFileSync(join(dir, "blocklist.json"), "{ torn", "utf8");
    assert.equal(store.getItem("blocklist"), undefined);
    assert.equal(readdirSync(dir).filter((f) => f.includes(".corrupt-")).length, 1);
    assert.equal(store.getItem("whitelist"), JSON.stringify([{ domain: "b.com" }]), "其他 key 不受牵连");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("migrateLegacyState：旧单文件 state.json 拆分为目录布局并保留备份", () => {
  const dir = mkdtempSync(join(tmpdir(), "citation-auditor-test-"));
  try {
    const legacy = {
      "rules/whitelist.json": JSON.stringify([{ domain: "legacy.com", reason: "", date: "" }]),
      "rules/blocklist.json": JSON.stringify([]),
      "rules/settings.json": JSON.stringify({ mode: "simple", ageQuery: { code: "(d)=>({creationDate:'2001-01-01'})", enabled: true } }),
      "cache/whois.json": JSON.stringify({}),
    };
    writeFileSync(join(dir, "state.json"), JSON.stringify(legacy, null, 2), "utf8");

    const code = migrateLegacyState(dir);
    assert.equal(code, "(d)=>({creationDate:'2001-01-01'})", "返回迁移出的年龄片段代码");
    assert.equal(new DirectoryStore(dir).getItem("whitelist"), legacy["rules/whitelist.json"]);
    assert.equal(new DirectoryStore(dir).getItem("settings"), legacy["rules/settings.json"]);
    assert.ok(!existsSync(join(dir, "state.json")), "旧文件已改名");
    assert.equal(readdirSync(dir).filter((f) => f.startsWith("state.json.migrated-")).length, 1, "旧文件改名保留");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AgeQueryFile：首次生成自带注释模板（契约+RDAP示例+注意事项），幂等不覆盖", () => {
  const dir = mkdtempSync(join(tmpdir(), "citation-auditor-test-"));
  try {
    const f = new AgeQueryFile(dir);
    f.ensure();
    const content = readFileSync(join(dir, "ageQuery.js"), "utf8");
    assert.match(content, /creationDate/);
    assert.match(content, /rdap/i);
    assert.match(content, /wikipedia\.org/, "注意事项包含测试固定域名");
    assert.match(content, /worker/, "注意事项说明 worker 执行模型");

    // 幂等：用户改过内容后 ensure 不得覆盖
    f.write("/* my custom */ (d) => undefined");
    f.ensure();
    assert.ok(readFileSync(join(dir, "ageQuery.js"), "utf8").includes("my custom"));

    // 迁移出的旧代码优先于内置模板
    const dir2 = mkdtempSync(join(tmpdir(), "citation-auditor-test-"));
    try {
      new AgeQueryFile(dir2).ensure("(d) => ({ creationDate: '2020-01-01' })");
      assert.ok(readFileSync(join(dir2, "ageQuery.js"), "utf8").includes("2020-01-01"));
    } finally {
      rmSync(dir2, { recursive: true, force: true });
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("Auditor：总开关关闭即完全休眠——空报表、零扫描、不触网", async () => {
  const dir = mkdtempSync(join(tmpdir(), "citation-auditor-test-"));
  try {
    const store = new DirectoryStore(dir);
    const ageFile = new AgeQueryFile(dir);
    ageFile.ensure();
    const auditor = new Auditor(store, ageFile);
    auditor.init();
    auditor.setEnabled(false);

    const out = await auditor.audit("看 https://spam.xyz/a 和 https://github.com/x");
    assert.equal(out.result.domains.length, 0, "休眠时不扫描");
    assert.equal(out.report, "");
    assert.equal(out.summary, null);

    // 重新启用后恢复正常（mtime 热重载让 settings.json 改动即刻生效）
    auditor.setEnabled(true);
    const out2 = await auditor.audit("看 https://github.com/x");
    assert.equal(out2.result.domains.length, 1);
    assert.ok(out2.report.includes("github.com"));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("Auditor：缓存命中标'缓存'，首次查询标'API查询'", async () => {
  const dir = mkdtempSync(join(tmpdir(), "citation-auditor-test-"));
  try {
    const store = new DirectoryStore(dir);
    const ageFile = new AgeQueryFile(dir);
    ageFile.ensure("(d) => ({ creationDate: '2012-02-11' })");
    const auditor = new Auditor(store, ageFile);
    auditor.init();
    const s = auditor.getSettings();
    s.ageQuery.enabled = true;
    s.mode = "simple";
    auditor.rules.saveSettings(s);

    const first = await auditor.audit("看 https://github.com/x");
    assert.equal(first.result.verdicts[0]!.sourceKind, "api_query", "首次查询走网络");
    const second = await auditor.audit("看 https://github.com/x");
    assert.equal(second.result.verdicts[0]!.sourceKind, "cache", "第二次命中缓存");
    assert.equal(second.result.verdicts[0]!.creationDate, "2012-02-11T00:00:00.000Z");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ---------- cache + ageQuery ----------

test("cache：ok 记录不可变，failed 可覆盖为 ok", () => {
  const { store, cleanup } = tempStore();
  try {
    const cache = new WhoIsCache(store);
    cache.noteFailed("x.com", "boom");
    assert.equal(cache.read("x.com")?.kind, "failed");
    cache.noteOk("x.com", "2010-01-01T00:00:00.000Z");
    assert.equal(cache.read("x.com")?.kind, "ok");
    cache.noteOk("x.com", "2020-01-01T00:00:00.000Z");
    const kept = cache.read("x.com");
    assert.equal(kept?.kind, "ok");
    assert.equal(kept?.kind === "ok" ? kept.creationDate : undefined, "2010-01-01T00:00:00.000Z", "已有 ok 记录保留原值");
  } finally {
    cleanup();
  }
});

test("ageQuery：编译错误与超时都安全返回，不抛出", async () => {
  const syntax = await queryAge("(function(){", "a.com", { timeoutMs: 200 });
  assert.equal(syntax.ok, false);
  assert.match(syntax.error ?? "", /语法错误/);

  const hang = await queryAge("async () => new Promise(() => {})", "a.com", { timeoutMs: 150 });
  assert.equal(hang.ok, false);
  // 永不定案的 Promise：worker 无活跃句柄会即刻退出，或被超时 terminate——两条路都安全
  assert.match(hang.error ?? "", /timeout|未返回结果/);

  const good = await queryAge("(d) => ({ creationDate: '2010-05-05' })", "a.com", { timeoutMs: 500 });
  assert.equal(good.ok, true);
  assert.equal(good.creationDate, "2010-05-05T00:00:00.000Z");

  const empty = await queryAge("", "a.com");
  assert.equal(empty.ok, false);
});

test("ageQuery：同步死循环不卡死主线程（worker_threads + terminate）", async () => {
  const start = Date.now();
  const r = await queryAge("() => { while (true) {} }", "a.com", { timeoutMs: 200 });
  const elapsed = Date.now() - start;
  assert.equal(r.ok, false);
  assert.match(r.error ?? "", /timeout/);
  assert.ok(elapsed < 3000, `主线程必须活着返回（实际 ${elapsed}ms）`);
  // 主线程还能继续干活
  const ok = await queryAge("(d) => ({ creationDate: '2010-01-01' })", "b.com", { timeoutMs: 500 });
  assert.equal(ok.ok, true);
});

test("ageQuery：返回裸字符串时报错提示期望契约", async () => {
  const r = await queryAge(`() => "2010-01-01"`, "a.com", { timeoutMs: 500 });
  assert.equal(r.ok, false);
  assert.match(r.error ?? "", /片段需返回 \{ creationDate/);
  assert.match(r.error ?? "", /string\(2010-01-01\)/);
});

test("ageQuery：makeAgeResolver 走缓存且失败可重试", async () => {
  const { store, cleanup } = tempStore();
  try {
    const cache = new WhoIsCache(store);
    const resolver = makeAgeResolver({
      code: `(d) => ({ creationDate: "2011-01-01" })`,
      enabled: true,
      cache: {
        read: (d) => cache.read(d),
        noteOk: (d, iso) => cache.noteOk(d, iso),
        noteFailed: (d, e) => cache.noteFailed(d, e),
      },
    });
    const first = await resolver("cached.com");
    assert.equal(first, "2011-01-01T00:00:00.000Z");
    const second = await resolver("cached.com");
    assert.equal(second, "2011-01-01T00:00:00.000Z");
    assert.equal(cache.read("cached.com")?.kind, "ok");

    // disabled → 直接 undefined，不触网
    const off = makeAgeResolver({ code: "(d) => ({ creationDate: '2011-01-01' })", enabled: false, cache: { read: () => undefined, noteOk: () => {}, noteFailed: () => {} } });
    assert.equal(await off("whatever.com"), undefined);
  } finally {
    cleanup();
  }
});

test("ageQuery：testAgeQuery 固定用 wikipedia.org（未启用片段时失败但不抛出）", async () => {
  const r = await testAgeQuery("(d) => ({ creationDate: '2001-01-15' })");
  assert.equal(r.ok, true);
});

// ---------- 插件元数据一致性（规范 §2.1.7 单一事实源） ----------

test("插件名与包名一致，状态路径解析不依赖 cwd", () => {
  const pkg = JSON.parse(readFileSync(new URL("../../package.json", import.meta.url), "utf8")) as { name: string };
  assert.equal(pluginName, pkg.name);

  const def = resolveStatePath("");
  assert.ok(def.includes(".citation-auditor"));
  assert.ok(!def.includes(process.cwd()), "默认路径不落在 process.cwd() 下");

  const custom = resolveStatePath("data/state.json");
  assert.ok(!custom.startsWith(process.cwd()), "相对路径按家目录解析，不依赖 cwd");
  assert.ok(existsSync(join(process.cwd(), "cordis.patch.yml")), "cordis.patch.yml 在包根");
});
