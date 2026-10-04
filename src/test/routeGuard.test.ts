/**
 * 路由来源校验测试（DSH 插件规范 §3.3.1 / §3.3.4）。
 *
 * 纯函数 + 内存 req/res 假件，不起真实服务器。覆盖的攻击面：
 * 恶意 Origin 的跨站请求、DNS rebinding（非回环 Host）、以及
 * 「不该误伤」的非浏览器客户端（curl / 脚本，没有 Origin 头）。
 */
import test from "node:test";
import assert from "node:assert/strict";
import type { IncomingMessage, ServerResponse } from "node:http";
import { PassThrough } from "node:stream";
import { checkRequestOrigin, guardRoute } from "../routeGuard.js";

/** 构造一个只带 headers 的假 IncomingMessage（不消费 body）。 */
function fakeReq(headers: Record<string, string | undefined>): IncomingMessage {
  return { headers } as unknown as IncomingMessage;
}

/** 收集响应状态的假 ServerResponse。 */
function fakeRes(): { res: ServerResponse; status: () => number; body: () => string; ended: () => boolean } {
  let statusCode = 0;
  let payload = "";
  let done = false;
  const res = {
    headersSent: false,
    writeHead(status: number) {
      statusCode = status;
      // @ts-expect-error 测试桩只需满足被调用的表面
      this.headersSent = true;
      return this;
    },
    // 测试桩只需满足被调用的表面；对象整体已在 as unknown as ServerResponse 处收窄。
    // 真实 end() 收到的是 Buffer，这里两种都收，否则 body 会是空串。
    end(chunk?: string | Buffer) {
      if (typeof chunk === "string") payload = chunk;
      else if (chunk !== undefined) payload = chunk.toString("utf8");
      done = true;
      return this;
    },
    destroy() {
      done = true;
      return this;
    },
  } as unknown as ServerResponse;
  return { res, status: () => statusCode, body: () => payload, ended: () => done };
}

// ---------- Host 校验（DNS rebinding 防线）----------

test("Host 非回环时拒绝（DNS rebinding 防线）", () => {
  assert.equal(checkRequestOrigin(fakeReq({ host: "evil.example" })).ok, false);
  assert.equal(checkRequestOrigin(fakeReq({ host: "evil.example" })).code, "bad-host");
  // 攻击者控制的域名解析到 127.0.0.1 —— Host 头仍是恶意域名，据此拒绝
  assert.equal(checkRequestOrigin(fakeReq({ host: "attacker.com:52720" })).code, "bad-host");
  assert.equal(checkRequestOrigin(fakeReq({ host: "192.168.1.5:8080" })).code, "bad-host");
});

test("回环 Host 放行（含 IPv6 与带端口）", () => {
  for (const host of ["127.0.0.1:8080", "localhost:5173", "[::1]:8080", "127.0.0.1"]) {
    assert.equal(checkRequestOrigin(fakeReq({ host })).ok, true, `${host} 应放行`);
  }
});

// ---------- Origin 校验（CSRF 防线）----------

test("跨站 Origin 拒绝，同源放行", () => {
  assert.equal(checkRequestOrigin(fakeReq({ host: "127.0.0.1:8080", origin: "https://evil.example" })).code, "bad-origin");
  assert.equal(checkRequestOrigin(fakeReq({ host: "127.0.0.1:8080", origin: "http://127.0.0.1:8080" })).ok, true);
  // 端口不同即不同源
  assert.equal(
    checkRequestOrigin(fakeReq({ host: "127.0.0.1:8080", origin: "http://127.0.0.1:9999" })).code,
    "bad-origin",
  );
  // 畸形 Origin 视为拒绝，不放行
  assert.equal(checkRequestOrigin(fakeReq({ host: "127.0.0.1:8080", origin: "notaurl" })).code, "bad-origin");
});

test("Origin: null（沙箱 iframe / data: 文档）拒绝", () => {
  assert.equal(checkRequestOrigin(fakeReq({ host: "127.0.0.1:8080", origin: "null" })).code, "bad-origin");
});

// ---------- Sec-Fetch-Site（浏览器不可伪造的信号）----------

test("Sec-Fetch-Site 跨站/同站拒绝", () => {
  assert.equal(checkRequestOrigin(fakeReq({ host: "127.0.0.1:8080", "sec-fetch-site": "cross-site" })).code, "bad-fetch-site");
  assert.equal(checkRequestOrigin(fakeReq({ host: "127.0.0.1:8080", "sec-fetch-site": "same-site" })).code, "bad-fetch-site");
  assert.equal(checkRequestOrigin(fakeReq({ host: "127.0.0.1:8080", "sec-fetch-site": "same-origin" })).ok, true);
  assert.equal(checkRequestOrigin(fakeReq({ host: "127.0.0.1:8080", "sec-fetch-site": "none" })).ok, true);
});

// ---------- 不得误伤非浏览器客户端 ----------

test("无 Origin 的非浏览器客户端放行（curl / 本地脚本）", () => {
  // 浏览器发起的跨站请求一定带 Origin；curl 不带。
  // CSRF 的前提是浏览器带着用户 cookie 发起，放行无 Origin 不会打开该口子。
  assert.equal(checkRequestOrigin(fakeReq({ host: "127.0.0.1:8080" })).ok, true);
  assert.equal(checkRequestOrigin(fakeReq({})).ok, true);
});

// ---------- 路由包装器行为 ----------

test("guardRoute：来源不合法时短路，不进入原 handler", () => {
  let called = false;
  const route = guardRoute({
    kind: "exact",
    path: "/api/citation-auditor/list",
    handler: () => {
      called = true;
    },
  });
  const { res, status, body, ended } = fakeRes();
  route.handler(fakeReq({ host: "evil.example" }), res);
  assert.equal(called, false, "恶意来源不得进入 handler");
  assert.equal(ended(), true);
  assert.equal(status(), 403);
  const parsed = JSON.parse(body()) as { ok: boolean; code: string };
  assert.equal(parsed.ok, false);
  assert.equal(parsed.code, "bad-host");
  // 错误响应不回显内部细节（§3.3.4）
  assert.ok(!body().includes("Traceback"));
});

test("guardRoute：只读端点同样校验（§3.3.1 禁止只读例外）", () => {
  let called = false;
  const route = guardRoute({ kind: "exact", path: "/api/citation-auditor/status", handler: () => { called = true; } });
  const { res, status } = fakeRes();
  route.handler(fakeReq({ host: "127.0.0.1:8080", origin: "https://evil.example" }), res);
  assert.equal(called, false);
  assert.equal(status(), 403);
});

test("guardRoute：合法同源请求放行到原 handler，且保持 kind/path", () => {
  let called = false;
  const route = guardRoute({ kind: "prefix", path: "/api/x", handler: () => { called = true; } });
  const { res } = fakeRes();
  route.handler(fakeReq({ host: "127.0.0.1:8080", origin: "http://127.0.0.1:8080" }), res);
  assert.equal(called, true);
  assert.equal(route.kind, "prefix");
  assert.equal(route.path, "/api/x");
});

test("guardRoute：handler 返回 promise 时透传", async () => {
  const route = guardRoute({
    kind: "exact",
    path: "/api/x",
    handler: async () => {
      await Promise.resolve();
    },
  });
  const { res } = fakeRes();
  const r = route.handler(fakeReq({ host: "127.0.0.1:8080" }), res);
  assert.ok(r instanceof Promise, "异步 handler 的返回值应原样透传");
  await r;
});

// 保持对 node:stream 的引用不被摇树掉（假件沿用其语义）
void PassThrough;
