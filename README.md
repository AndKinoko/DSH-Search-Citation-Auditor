# -DSH_WEB_Citation-Auditor
审查 AI 回复里的引用来源：把回复中的 URL 提取出来，按威胁度打分排序，输出报表；**拦截名单里的域名会被真正禁止访问**（web_search / web_fetch 等 web 工具直接拒绝）。名单完全归用户维护，处置权在你手上。 Cordis 函数插件，可被 DeepSeek Harness 直接加载。业务内核（scanner / scorer / report）是纯函数，脱离 dsh 也能复用。
