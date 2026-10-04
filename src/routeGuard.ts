/**
 * 本地 HTTP 端点的来源校验（DSH 插件规范 §3.3.1 / §3.3.4）。
 *
 * 为什么必须插件自己做：`dsh-host-webserver` 的 README 明确写了
 * 「不提供 TLS、认证或来源策略」。webserver 只负责把原始 req/res 交给路由，
 * 来源判断没有任何宿主兜底。而本插件的端点能改名单、改设置、唤起系统程序，
 * 缺这道校验意味着任意网页发个请求就能改用户配置——这正是 §3.3.5 点名要防的
 * DNS rebinding / CSRF。
 *
 * 三道校验（与 §3.3.1 逐项对应）：
 *  1. **Host** 必须是回环（127.0.0.1 / localhost / [::1]）。DNS rebinding 会让
 *     恶意域名的解析指向 127.0.0.1，此时 Host 头是恶意域名而非回环名，据此拒绝。
 *  2. **Origin** 若存在，必须与 Host 同源。浏览器发起的跨站请求一定带 Origin；
 *     跨站表单/fetch 的 Origin 不等于本机 Host，据此拒绝。
 *  3. **Sec-Fetch-Site** 若存在且为 cross-site / same-site，直接拒绝——这是
 *     浏览器强制提供的、不可被 JS 伪造的同源信号。
 *
 * 三道都过不了的极端情况（无 Host、无 Origin、无 Sec-Fetch-Site）才放行：
 * 那是 curl / 脚本等非浏览器客户端，没有浏览器会自动补 Origin，不该被误伤。
 * 这类请求同样打不到 CSRF——CSRF 的前提是浏览器带着用户 cookie 自动发起。
 *
 * 纯函数、无 IO。checkRequest 便于单测；guardRoute 是路由包装器。
 */
import type { IncomingMessage, ServerResponse } from "node:http";
import type { WebRoute } from "@deepseek-ai/dsh-host-webserver";

/**
 * 回环主机名：浏览器与本地工具都用这几个。
 *
 * 刻意不含 "0.0.0.0"：那不是回环地址，是「绑定所有网卡」的通配监听——而
 * dsh-host-webserver 的 Config 明确支持它（`host: z.union([z.const("127.0.0.1"),
 * z.const("0.0.0.0")])`，注释原话 "loopback and all-interfaces"）。一旦宿主按全
 * 网卡绑定，局域网里任何非浏览器客户端只要发一个 `Host: 0.0.0.0` 就能通过下面
 * 第一道校验；而 Origin / Sec-Fetch-Site 它压根不会发送——那两道是浏览器才自动补
 * 的，非浏览器客户端可以合法缺席，于是三道全过。
 *
 * 同理移除 "[::1]"：hostnameOf 会先剥掉方括号，带括号的形态永远匹配不上，是死条目。
 *
 * 边界要说清楚：本模块是 **CSRF 防护，不是认证**（见 §3.3.4）。所有判据都是请求头，
 * 非浏览器客户端可以任意设置。它挡的是「恶意网页借用户浏览器发请求」，不是
 * 「同网段的主机直接连过来」。
 */
const LOOPBACK_HOSTS = new Set(["127.0.0.1", "localhost", "::1"]);

/** 判定结果：ok=true 放行，false 时带一个固定 code（不回显内部细节，见 §3.3.4）。 */
export interface OriginCheck {
  ok: boolean;
  code?: "bad-host" | "bad-origin" | "bad-fetch-site";
}

/** 取 Host 头（HTTP/1.1；HTTP/2 下为 :authority，node 归一到 host 头）。 */
function hostOf(req: IncomingMessage): string {
  // 防御：路由的 req 在真实服务器上一定有，但测试桩 / 异常构造可能缺 headers。
  // 校验层绝不能因为请求形状异常而抛——抛出会绕过 reject() 走进 500，
  // 与「统一固定文案」的要求相悖。缺 headers 一律按「无 Host」处理。
  const raw = req?.headers?.host;
  if (typeof raw !== "string") return "";
  return raw.trim().toLowerCase();
}

/** 拆出 hostname 部分，剥掉端口；IPv6 的 [::1]:8080 也能正确剥。 */
function hostnameOf(hostHeader: string): string {
  const bracketed = /^\[([^\]]*)\](?::\d+)?$/.exec(hostHeader);
  if (bracketed) return bracketed[1] ?? "";
  const colon = hostHeader.lastIndexOf(":");
  return colon === -1 ? hostHeader : hostHeader.slice(0, colon);
}

/**
 * 校验一次请求的来源。三道校验全过才放行。
 * @param req 入站请求（只读 headers，不消费 body）。
 * @returns 放行与否；拒绝时带固定 code。
 */
export function checkRequestOrigin(req: IncomingMessage): OriginCheck {
  // 1) Host 必须是回环
  const hostHeader = hostOf(req);
  if (hostHeader !== "") {
    const hostname = hostnameOf(hostHeader);
    if (!LOOPBACK_HOSTS.has(hostname)) return { ok: false, code: "bad-host" };
  }

  // 2) Sec-Fetch-Site：浏览器强制提供，不可伪造
  const site = req?.headers?.["sec-fetch-site"];
  if (typeof site === "string") {
    const value = site.trim().toLowerCase();
    if (value === "cross-site" || value === "same-site") return { ok: false, code: "bad-fetch-site" };
  }

  // 3) Origin 若存在必须同源
  const origin = req?.headers?.origin;
  if (typeof origin === "string" && origin !== "") {
    let originHost: string;
    try {
      originHost = new URL(origin).host.toLowerCase();
    } catch {
      // "null"（sandbox iframe / data: 文档 / 隐私窗口的 opaque origin）在这里
      // 解析失败。它不是"没有 Origin"，而是一个真实的、不可信的来源，必须拒绝。
      return { ok: false, code: "bad-origin" };
    }
    // Host 缺失时无法比对，退回「Sec-Fetch-Site 已判过」放行
    if (hostHeader !== "" && originHost !== hostHeader) return { ok: false, code: "bad-origin" };
  }

  return { ok: true };
}

/** 拒绝时的固定响应：状态码 + 文案都不含内部细节（§3.3.4）。 */
function reject(res: ServerResponse, code: string): void {
  const body = Buffer.from(JSON.stringify({ ok: false, error: "forbidden", code }), "utf8");
  if (res.headersSent) {
    res.destroy();
    return;
  }
  res.writeHead(403, {
    "content-type": "application/json; charset=utf-8",
    "content-length": String(body.byteLength),
    "cache-control": "no-store",
  });
  res.end(body);
}

/**
 * 包装一条路由：来源校验不通过则短路，不进入原 handler。
 * §3.3.1 明确「只读路由无例外」，所以 status 这类 GET 也照样校验。
 *
 * @param route 原始路由。
 * @returns 同样 kind/path、handler 被包上校验的新路由。
 */
export function guardRoute(route: WebRoute): WebRoute {
  const inner = route.handler;
  return {
    kind: route.kind,
    path: route.path,
    handler: (req, res) => {
      const verdict = checkRequestOrigin(req);
      if (!verdict.ok) {
        reject(res, verdict.code ?? "forbidden");
        return;
      }
      return inner(req, res);
    },
  };
}

/** 批量包装（导出便于单测与 index 侧复用）。 */
export function guardRoutes(routes: WebRoute[]): WebRoute[] {
  return routes.map(guardRoute);
}
