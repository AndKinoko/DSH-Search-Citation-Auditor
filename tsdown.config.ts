/**
 * client bundle 构建配置（仿 harness packages/client/tsdown.client.ts 的产物形态）。
 *
 * 产物 lib/client.js 是一个 CJS 闭包工厂：banner 调用
 * `window.__ModuleLoader__.load({ id, factory })`，所有平台依赖经注入的
 * require（loader 模块表）解析——不落全局、不用 import map。平台模块保持
 * external，其余（本插件自身代码、纯工具库）全部内联。
 *
 * host 半边（lib/index.js 等）仍由 tsc 产出；本配置只追加 client 产物。
 */
import { defineConfig } from "tsdown";

/** 插件标识：盖进 __ModuleLoader__.load 的 id 与注入的 <style data-plugin> 标签。 */
const PLUGIN_ID = "dsh-citation-auditor";

/**
 * loader 模块表能应答的 external：浏览器平台种子模块（react 系、cordis、
 * ui-slots、ui 原语）+ dsh.client.facet 声明 inject 的 client 包。
 * 表答不了的 require 是运行时必炸——所以其余一律内联（noExternal）。
 */
const EXTERNALS = [
  "react",
  "react/jsx-runtime",
  "react-dom",
  "react-dom/client",
  "@deepseek-ai/cordis",
  "@deepseek-ai/dsh-client-ui-slots",
  "@deepseek-ai/dsh-client-web-react",
  "@deepseek-ai/dsh-client-ui-primitives",
  "@deepseek-ai/dsh-client-runtime/client",
  "@deepseek-ai/dsh-client-connection",
  "@deepseek-ai/dsh-client-ui-settings/client",
  "@deepseek-ai/dsh-client-ui-conversation/client",
] as const;

export default defineConfig([
  {
    name: `${PLUGIN_ID}/client`,
    entry: { client: "src/client/index.ts" },
    outDir: "lib",
    format: "cjs",
    platform: "browser",
    dts: false,
    sourcemap: true,
    clean: false, // 不能清 lib/：tsc 的 host 半边产物在同一目录
    external: [...EXTERNALS],
    noExternal: (id: string) => (EXTERNALS.includes(id as (typeof EXTERNALS)[number]) ? undefined : true),
    define: {
      "process.env.NODE_ENV": JSON.stringify(process.env.NODE_ENV ?? "production"),
      "import.meta.env.MODE": JSON.stringify(process.env.NODE_ENV ?? "production"),
      "import.meta.env": JSON.stringify({ MODE: process.env.NODE_ENV ?? "production" }),
    },
    outputOptions: {
      entryFileNames: "client.js",
      banner: `window.__ModuleLoader__.load({ id: ${JSON.stringify(PLUGIN_ID)}, factory: (require) => {`,
      footer: "return module.exports; } });",
      intro: "var module = { exports: {} }; var exports = module.exports;",
    },
  },
]);
