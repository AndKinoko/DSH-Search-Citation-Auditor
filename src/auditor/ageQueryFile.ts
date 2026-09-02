/**
 * ageQuery.js 独立文件管理。
 * "编辑JS代码" = 用任何编辑器打开这个文件，保存即生效（审计时每次重新读取）。
 * 首次生成时自动写入注释模板（契约 + 可运行 RDAP 示例 + 注意事项）。
 */
import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { atomicWrite } from "../storage.js";

export const AGE_QUERY_TEMPLATE = `/**
 * Citation Auditor 年龄查询片段（唯一联网点）
 *
 * 入参: domain（注册域字符串，如 wikipedia.org）、fetch（全局 fetch）
 * 出参: 必须返回 { creationDate: <ISO 日期字符串或毫秒数字> } 对象；查不到返回 undefined
 *      （返回 undefined 按可疑级处理，不会误标红；返回裸字符串会直接报错）
 *
 * 注意事项:
 *  - 片段在 worker 线程里执行，5 秒超时直接 terminate；但同步死循环依旧禁止——
 *    写 while(true){} 会让该次查询超时失败（主进程不受影响，测试也过不了）
 *  - RDAP 只认注册域不认子域（本插件传入的 domain 已按 PSL 归一化，无需处理）
 *  - [测试] 固定用 wikipedia.org 跑一次本文件；测试不通过的片段无法启用
 *  - 本文件保存即生效，无需重启
 */
async (domain, fetch) => {
  const tld = domain.split('.').pop();
  const regs = {
    com: 'https://rdap.verisign.com/com/v1/domain/',
    net: 'https://rdap.verisign.com/net/v1/domain/',
    org: 'https://rdap.publicinterestregistry.org/rdap/domain/',
    top: 'https://rdap.centralnic.com/domain/',
    xyz: 'https://rdap.centralnic.com/domain/',
  };
  const base = regs[tld] || 'https://rdap.org/domain/';
  try {
    const res = await fetch(base + domain, { signal: AbortSignal.timeout(4000) });
    if (!res.ok) return undefined;
    const j = await res.json();
    const ev = (j.events || []).find((e) => e.eventAction === 'registration');
    return ev ? { creationDate: ev.eventDate } : undefined;
  } catch { return undefined; }
}
`;

export class AgeQueryFile {
  readonly #file: string;

  constructor(dir: string) {
    this.#file = join(dir, "ageQuery.js");
  }

  /** 首次生成：写入注释模板 + 片段（优先用迁移出的旧代码，否则用内置 RDAP 示例）。幂等。 */
  ensure(seedCode = ""): void {
    if (existsSync(this.#file)) return;
    const body = seedCode.trim() !== "" ? seedCode.trimEnd() + "\n" : AGE_QUERY_TEMPLATE;
    atomicWrite(this.#file, body);
  }

  /** 读取当前片段（含注释，注释不影响求值）。文件缺失返回 ""。 */
  read(): string {
    try {
      return readFileSync(this.#file, "utf8");
    } catch {
      return "";
    }
  }

  /** 整体覆写（保留给"恢复默认模板"类操作用）。 */
  write(content: string): void {
    atomicWrite(this.#file, content);
  }

  /** 恢复内置模板。 */
  reset(): void {
    this.write(AGE_QUERY_TEMPLATE);
  }
}
