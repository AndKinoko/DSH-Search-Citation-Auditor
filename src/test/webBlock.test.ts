/**
 * 真实拦截（web 访问阻断）测试：
 *  - RuleStore.blocks：精确域名 / TLD 后缀命中；白名单不参与
 *  - blockedToolDecision：从工具参数提取 URL → 域名 → 命中即 deny
 */
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { Auditor } from "../auditor/service.js";
import { AgeQueryFile } from "../auditor/ageQueryFile.js";
import { DirectoryStore } from "../storage.js";
import { blockedToolDecision } from "../webBlock.js";

function makeAuditor(dir: string): Auditor {
  const store = new DirectoryStore(dir);
  const ageFile = new AgeQueryFile(dir);
  ageFile.ensure("");
  const auditor = new Auditor(store, ageFile);
  auditor.init();
  return auditor;
}

test("blocks：精确域名命中", () => {
  const dir = mkdtempSync(join(tmpdir(), "citation-auditor-test-"));
  try {
    const auditor = makeAuditor(dir);
    auditor.rules.addToBlocklist("reuters.com", "手动标记");
    assert.equal(auditor.rules.blocks("reuters.com"), true);
    assert.equal(auditor.rules.blocks("wikipedia.org"), false, "未拦的域名放行");
    // 子域经 PSL 归一化后命中注册域
    assert.equal(auditor.rules.blocks("www.reuters.com"), false, "blocks 输入是注册域，子域由 scanner 先归一化");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("blocks：TLD 后缀命中（.shop 拦 example-abc123.shop）", () => {
  const dir = mkdtempSync(join(tmpdir(), "citation-auditor-test-"));
  try {
    const auditor = makeAuditor(dir);
    auditor.rules.addToBlocklist(".shop", "高滥用电商 TLD");
    assert.equal(auditor.rules.blocks("example-abc123.shop"), true);
    assert.equal(auditor.rules.blocks("example.com"), false, "无关域名放行");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("blockedToolDecision：web_fetch 参数里的被拦 URL 被拒绝", () => {
  const dir = mkdtempSync(join(tmpdir(), "citation-auditor-test-"));
  try {
    const auditor = makeAuditor(dir);
    auditor.rules.addToBlocklist("malwaretips.com", "手动标记");
    auditor.rules.addToBlocklist(".top", "预写");
    const denied = blockedToolDecision(auditor, "web_fetch", { url: "https://malwaretips.com/how-to" });
    assert.ok(denied, "精确命中应拒绝");
    assert.equal(denied!.kind, "deny");
    assert.match(denied!.reason, /malwaretips\.com/);
    assert.equal(blockedToolDecision(auditor, "tool:web_fetch", { url: "https://some-new-xyz.top/offer" })?.kind, "deny", "TLD 命中应拒绝");
    assert.equal(blockedToolDecision(auditor, "web_fetch", { url: "https://github.com/deepseek-ai" }), undefined, "未拦域名放行");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("blockedToolDecision：web_search 查询里带被拦裸域名也拒绝；空参数/非 web 工具放行", () => {
  const dir = mkdtempSync(join(tmpdir(), "citation-auditor-test-"));
  try {
    const auditor = makeAuditor(dir);
    auditor.rules.addToBlocklist("reuters.com", "手动标记");
    assert.equal(blockedToolDecision(auditor, "web_search", { query: "reuters.com 最新新闻" })?.kind, "deny", "查询里带裸被拦域名应拒绝");
    assert.equal(blockedToolDecision(auditor, "web_search", { query: "今天天气怎么样" }), undefined);
    assert.equal(blockedToolDecision(auditor, "web_search", undefined), undefined);
    // 非 web 工具（含插件自己的 citation_audit）不拦截——审计文本本来就可能含被拦域名
    assert.equal(blockedToolDecision(auditor, "citation_audit", { text: "看 https://reuters.com/a" }), undefined);
    assert.equal(blockedToolDecision(auditor, "bash", { command: "curl https://reuters.com" }), undefined, "shell 通道不在拦截范围");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
