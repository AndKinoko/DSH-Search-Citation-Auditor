# Citation Auditor
<img width="1280" height="704" alt="大肥鱼" src="https://github.com/user-attachments/assets/700a5a9e-b5ae-4156-8357-08daf81b34b4" />

审查 AI 回复里的引用来源：把回复中的 URL 提取出来，按威胁度打分排序，输出报表；**拦截名单里的域名会被真正禁止访问**（web_search / web_fetch 等 web 工具直接拒绝）。名单完全归用户维护，处置权在你手上。

[Cordis](https://github.com/deepseek-ai/deepseek-harness) 函数插件，可被 [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness) 直接加载。业务内核（scanner / scorer / report）是纯函数，脱离 dsh 也能复用。

## 工作效果
### 打分机制（当前打分机制非常简单，打分机制的细化为todo事项，我暂时没有什么好的想法，欢迎提issue）

| 模式 | 打分函数 | 判断维度 | 核心规则 | 典型分值 |
| --- | --- | --- | --- | --- |
| whitelist | scoreWhitelist | 纯名单二元判定 | 命中白名单 → trusted；否则一律 critical | 0 / 100 |
| simple | scoreSimple | 域名注册年龄 | 注册于 2023 年前 → trusted；2023 年及以后 → critical；查不到年龄 → critical（treatAsNew） | 0 / 100 |
| normal | scoreNormal | 多信号累加 | TLD 拦截、连字符/数字、长度、注册年龄、年龄可验证性分别累加 | 0–100 |

<img width="1541" height="820" alt="QQ20260903-011153" src="https://github.com/user-attachments/assets/7d8082ae-d209-4af4-9538-3c118bb4f9ae" />

### 拦截成功的效果如图
<img width="1556" height="730" alt="QQ20260903-011055" src="https://github.com/user-attachments/assets/b1ee50ba-b40d-4875-ad97-e29c531d8e89" />

## 工作方式

扫描文本 → 提取 URL → PSL 解析注册域（eTLD+1）→ 0–100 打分 → 出报表。

三种模式：

- **白名单模式**：名单内绿，名单外全红。最严。
- **简单模式**：2023 年前注册的可信，之后标红。
- **普通模式**：多信号综合评分（TLD、连字符/数字个数、域名长度、注册年龄）。

命中拦截名单的域名直接标红，不参与评分；精确域名与 `.xyz`/`.shop` 这类 TLD 条目都受**当前模式**的拦截名单开关控制（开关关闭 = 该模式完全不应用名单）。域名匹配统一按注册域：`en.wikipedia.org` → `wikipedia.org`。年龄查不到时只记"可疑"（ageQuery 未启用或查询失败），只有确认是新域名才从严标红。

**真实拦截**：拦截名单（含 `.shop` 这类 TLD 条目）会在 `tools/pre-execute` 阶段拦截 web 工具（web_search / web_fetch 等），命中即拒绝调用并告知模型原因——加入名单后模型就访问不了该网页了。只拦 web 工具；pwsh/curl 等 shell 通道属沙箱层，不在拦截范围。名单增删（界面按钮或直接改 blocklist.json）即时生效，无需重启。

向 dsh 注册两个工具：

| 工具 | 作用 |
|---|---|
| `citation_audit` | 审计一段文本，返回结构化结果 + 纯文本报表 |
| `citation_manage` | 查状态、启停、切模式、增删名单、测试年龄片段 |

## Web 界面

- **设置页卡片**：三种模式单选、各模式拦截名单开关、白名单免查加速、插件总开关、年龄片段 [编辑JS代码] 与 [测试]（固定 wikipedia.org）。名单旁的 [查看/编辑] 用系统默认程序打开对应 JSON，改完即生效。
- **交互报表**：会话里 `citation_audit` 渲染成可点报表，非可信域名带 [➕ 加入拦截名单] / [➕ 加入白名单] / [忽略]；拦截名单开关关闭时弹窗三选（开启并保存 / 仅保存 / 取消）。写入后按钮变灰，可再点确认移除。
- **悬浮窗**：右下角可拖动球（有可疑域名时显示红色角标），点击展开最近回复的网址列表与分数；面板内含 ⚙ 设置入口和同样的名单按钮。悬浮窗按宿主实际能力取会话节点：新宿主优先订阅 `uiConversation` 的 chat 通道（`legacy.nodes`），旧宿主回退会话快照自带的 nodes。

所有设置/名单读写都走插件自有的同源端点 `/api/citation-auditor/*`（status / audit / list / settings / test-age / open-file），直接落盘 `settings.json`，不依赖 harness 的 settings 服务。

## 年龄查询片段（唯一联网点）

一段你自己写的 JS，在 worker 线程执行，5 秒超时直接 terminate（同步死循环也拖不垮主线程）。契约：必须返回 `{ creationDate: <ISO 日期或毫秒> }` 对象，查不到返回 `undefined`。先测试后启用，默认关闭。

按 TLD 分发注册局直连的 RDAP 示例（可直接粘贴进 `ageQuery.js`）：

```js
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
```

局限：RDAP 只认注册域（已按 PSL 归一化，天然满足）；.cn 等部分 ccTLD 无公开 RDAP 或被网络阻断会查不到；新 gTLD（如 .top）数据不一定齐全。

## 数据与安全

名单、设置、年龄缓存各自存成独立 JSON 文件（默认 `~/.citation-auditor/`，配置 `statePath` 可改），外加可编辑的 `ageQuery.js`。写入走临时文件 + fsync + rename 原子发布；损坏先备份为 `*.corrupt-*` 再处理，绝不覆盖；每次读取检查 mtime，直接改文件保存即生效。旧版单文件 state.json 首次启动自动迁移。

报表永不改写 AI 原文；全项目唯一的联网点是你的年龄查询片段。

## 构建与安装

```bash
npm install
npm run typecheck   # tsc --noEmit
npm run test        # 构建 + node:test（50 项）
```

安装进 dsh profile：发布 npm 包或 `dsh plugin --profile web add https://github.com/AndKinoko/DSH-Search-Citation-Auditor`（`prepare` 脚本自动构建）。配置只有一个字段：

```yml
- insert:
    - id: dsh-citation-auditor
      name: dsh-citation-auditor
      config:
        statePath: ""   # 留空用 ~/.citation-auditor
```

client 半边要求宿主 `dsh.engines.dsh >= 0.1.1-rc.1`（host 工具无此门槛）。

## 目录结构

```
src/
├── index.ts           # Cordis 插件入口（name/inject/Config/apply + 两个工具）
├── storage.ts         # 目录化键值存储（每 key 一文件 + mtime 热重载 + 原子写）
├── routes.ts          # /api/citation-auditor/* 数据端点
├── settingsSection.ts # 设置命名空间 host 半边
├── client/            # 浏览器半边（设置卡片 / 交互报表 / 悬浮窗）
├── test/              # node:test 一致性测试
└── auditor/           # 业务内核（scanner/scorer/report 纯函数 + rules/cache/ageQuery）
```

## License

MIT，见 [LICENSE](./LICENSE)。
