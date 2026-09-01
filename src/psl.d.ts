/**
 * psl 的本地类型声明。
 * psl@1.15 的 package.json exports 映射缺 "types" 条目，NodeNext 解析不到
 * 它自带的 types/index.d.ts（TS7016）。声明与其实际 ESM 导出（dist/psl.mjs）一致。
 */
declare module "psl" {
  export interface ParsedDomain {
    input: string;
    tld: string | null;
    sld: string | null;
    domain: string | null;
    subdomain: string | null;
    listed: boolean;
  }
  export function get(domain: string): string | null;
  export function parse(domain: string): ParsedDomain;
  export function isValid(domain: string): boolean;
}
