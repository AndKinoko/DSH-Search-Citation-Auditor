/**
 * ageQuery：全项目唯一联网点。
 * 用 new Function 执行 settings.ageQuery.code（用户纯文本 JS），无沙箱直接执行。
 * 信任模型：配置文件本就 100% 用户领地，能改配置即能为所欲为，沙箱无意义；
 * 防护目标是防用户写错代码拖垮常驻进程。
 *
 * 执行模型：用户代码在 worker_threads 线程里跑，主线程超时即 worker.terminate()。
 * Promise.race 只能救 async/网络挂起，救不了同步死循环（while(true) 会卡死事件循环，
 * 超时永远不触发）——所以真正的执行隔离必须跨线程。片段编译（new Function 只编译
 * 不执行）仍在主线程做，语法错误无需起线程就能拦截。
 *
 * 规则：
 *  - 只注入 domain + fetch，不做其它注入、不关 API。
 *  - 默认 5 秒超时：同步死循环与网络挂起都会被 terminate（本次查询放弃，不中断常驻进程）。
 *  - 错误原样透传（"查询失败: <原始错误信息>"，不做友好包装）。
 *  - 片段必须先通过 test 才能启用（死循环/语法错误在配置阶段拦截）。
 *
 * 本模块自身不做任何网络请求；唯一发起的网络调用是用户代码里的 fetch。
 */
import { Worker } from "node:worker_threads";

export interface AgeQueryResult {
  ok: boolean;
  creationDate?: string; // ISO 字符串，new Date(creationDate) 能认即可
  error?: string;
}

const DEFAULT_TIMEOUT_MS = 5000;

function compile(code: string): unknown {
  // 包装为用户函数：async/普通函数皆可。只编译不执行，语法错误在此暴露。
  return new Function("domain", "fetch", `"use strict"; return (${code})(domain, fetch);`);
}

/** worker 引导脚本：eval 模式（CommonJS），执行用户片段并把结果/错误发回主线程。 */
const WORKER_BOOT = `
const { parentPort, workerData } = require("node:worker_threads");
try {
  const compiled = new Function("domain", "fetch", '"use strict"; return (' + workerData.code + ')(domain, fetch);');
  Promise.resolve(compiled(workerData.domain, fetch)).then(
    (value) => parentPort.postMessage({ value }),
    (err) => parentPort.postMessage({ error: String((err && err.message) || err) }),
  );
} catch (err) {
  parentPort.postMessage({ error: String((err && err.message) || err) });
}
`;

type WorkerOutcome = { value?: unknown; error?: string };

/** 描述片段的实际返回值，用于报错提示期望契约。 */
function describeValue(v: unknown): string {
  if (v === undefined) return "undefined";
  if (v === null) return "null";
  const t = typeof v;
  if (t === "string" || t === "number" || t === "boolean") return `${t}(${String(v)})`;
  try {
    const s = JSON.stringify(v);
    return s !== undefined && s.length <= 60 ? `object(${s})` : "object";
  } catch {
    return "object";
  }
}

/** 在独立线程执行用户片段；超时 terminate，同步死循环也不会卡住主线程。 */
function runUserCodeInWorker(code: string, domain: string, timeoutMs: number): Promise<WorkerOutcome> {
  return new Promise((resolve) => {
    // CPU 隔离由超时 + terminate() 提供；但**内存**此前完全不受限：一个持续分配
    // 的片段能把宿主进程 RSS 推到 4000 MB 才被 5s 超时杀掉——小内存机器上直接 OOM，
    // 而这恰恰是本模块声称要防的「拖垮常驻进程」。resourceLimits 让越界的 worker
    // 自己抛出 RangeError 并退出。
    // execArgv: [] 另有一层好处：宿主若带 --inspect 启动，每个 worker 都会去抢同一个
    // 调试端口而失败。
    const worker = new Worker(WORKER_BOOT, {
      eval: true,
      workerData: { code, domain },
      resourceLimits: {
        maxOldGenerationSizeMb: 256,
        maxYoungGenerationSizeMb: 32,
        stackSizeMb: 4,
      },
      execArgv: [],
    });
    let settled = false;
    const finish = (outcome: WorkerOutcome) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      void worker.terminate();
      resolve(outcome);
    };
    const timer = setTimeout(() => finish({ error: `age query timeout (>${timeoutMs}ms)` }), timeoutMs);
    worker.on("message", (msg: WorkerOutcome) => finish(msg));
    worker.on("error", (err: Error) => finish({ error: String(err.message ?? err) }));
    worker.on("exit", (code_: number) => {
      // code 0 = 片段的 Promise 永不定案且无活跃句柄，worker 事件循环自然排空（比等超时更快，同样安全）
      finish({ error: code_ === 0 ? "片段未返回结果（返回的 Promise 未落定即退出）" : `worker 异常退出（code ${code_}）` });
    });
  });
}

/**
 * 对指定域名执行用户年龄查询片段。
 * 调用方需自行把返回的 creationDate 传入 scorer。
 * 传入自定义 fetchImpl 时退回主线程执行（仅测试用；主线程执行防不住同步死循环）。
 */
export async function queryAge(
  code: string,
  domain: string,
  opts: { fetchImpl?: typeof fetch; timeoutMs?: number } = {},
): Promise<AgeQueryResult> {
  const { fetchImpl, timeoutMs = DEFAULT_TIMEOUT_MS } = opts;
  if (!code || code.trim() === "") {
    return { ok: false, error: "未配置年龄查询片段（settings.ageQuery.code 为空）" };
  }
  try {
    compile(code);
  } catch (err) {
    return { ok: false, error: `语法错误无法编译: ${err instanceof Error ? err.message : String(err)}` };
  }
  try {
    const outcome =
      fetchImpl === undefined
        ? await runUserCodeInWorker(code, domain, timeoutMs)
        : await Promise.race([
            // Promise.resolve 包一层：片段同步返回普通对象（非 Promise）也能落定
            Promise.resolve(
              (compile(code) as (d: string, f: typeof fetch) => Promise<{ creationDate?: string | number }> | { creationDate?: string | number })(
                domain,
                fetchImpl,
              ),
            ).then(
              (value): WorkerOutcome => ({ value }),
              (err: unknown): WorkerOutcome => ({ error: String((err as Error)?.message ?? err) }),
            ),
            new Promise<WorkerOutcome>((res) =>
              setTimeout(() => res({ error: `age query timeout (>${timeoutMs}ms)` }), timeoutMs),
            ),
          ]);
    if (outcome.error !== undefined) {
      return { ok: false, error: `查询失败: ${outcome.error}` };
    }
    const result = outcome.value as { creationDate?: string | number } | undefined;
    const cd = result?.creationDate;
    if (cd === undefined || cd === null || cd === "") {
      return {
        ok: false,
        error: `片段需返回 { creationDate: <ISO 日期字符串或毫秒数字> } 对象（当前实际返回: ${describeValue(result)}）`,
      };
    }
    const iso = new Date(cd).toISOString();
    if (Number.isNaN(Date.parse(iso))) {
      return {
        ok: false,
        error: `无法解析 creationDate: ${String(cd)}（需 ISO 日期字符串或毫秒数字）`,
      };
    }
    return { ok: true, creationDate: iso };
  } catch (err) {
    // 错误原样透传，不做友好包装
    return { ok: false, error: `查询失败: ${err instanceof Error ? err.message : String(err)}` };
  }
}

/** 固定用 wikipedia.org 跑一次（"测试"操作）。 */
export async function testAgeQuery(
  code: string,
  opts: { fetchImpl?: typeof fetch; timeoutMs?: number } = {},
): Promise<AgeQueryResult> {
  return queryAge(code, "wikipedia.org", opts);
}

export interface DomainAgeResolver {
  (domain: string): Promise<string | undefined>;
}

/** 组装带缓存 + 失败重试的解析器（供扫描流程使用）。 */
export function makeAgeResolver(spec: {
  code: string;
  enabled: boolean;
  cache: { read(domain: string): { kind: string; creationDate?: string } | undefined; noteOk(d: string, iso: string): void; noteFailed(d: string, e: string): void };
}): DomainAgeResolver {
  return async (domain: string): Promise<string | undefined> => {
    if (!spec.enabled || !spec.code.trim()) return undefined;
    const cached = spec.cache.read(domain);
    if (cached && cached.kind === "ok" && cached.creationDate) {
      return cached.creationDate; // 不可变事实，直接命中
    }
    const r = await queryAge(spec.code, domain);
    if (r.ok && r.creationDate) {
      spec.cache.noteOk(domain, r.creationDate);
      return r.creationDate;
    }
    spec.cache.noteFailed(domain, r.error ?? "unknown");
    return undefined;
  };
}