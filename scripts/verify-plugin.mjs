#!/usr/bin/env node
/**
 * DSH 插件规范合规校验器（DSH Plugin Standard §8 合规门禁）
 *
 * 独立分发：本文件自包含、无外部依赖，可复制到任何插件仓库，或通过
 * `npx dsh-plugin-standard <dir>` 运行。权威规范见 dsh-plugin-standard/STANDARD.md。
 *
 * 用法：
 *   node scripts/verify-plugin.mjs [插件目录] [--pack] [--koishi] [--compat] [--json] [--version] [--help]
 *
 * 退出码：
 *   0 = 无 MUST 违规
 *   1 = 存在 MUST 违规（不得发布/装配）
 *   2 = 目录不可用或参数错误
 *
 * --koishi 兼容模式（生态桥 F1）：
 *   自动识别 koishi 插件（包名 koishi-plugin-* 或 peerDependencies.koishi）即启用，
 *   也可 --koishi 强制。跳过 DSH 专属 MUST（2.1.1 type/2.1.3 client/2.1.4 bundle patch），
 *   改跑 koishi 兼容检查集（KO1 peerDeps.koishi、KO2 main、KO3 安全/生命周期红线）。
 *   语义：门槛级 Compliant（结构合规 + shim 覆盖），非 DSH 原生合规。
 *
 * 检查范围对应 STANDARD.md 的 §2 / §6：
 *   - 2.1.1 type module
 *   - 2.1.2 main/types/exports 指向真实产物
 *   - 2.1.3 client 声明与 ./client 同时出现
 *   - 2.1.4 dsh.bundle.patch 指向真实顶层数组 YAML
 *   - 2.1.6 @deepseek-ai 不得进 dependencies
 *   - 2.1.7 包名一致性（patch name / src export scope / client wrapper id）
 *   - 2.2.1/2.2.4 patch 顶层数组、id 唯一、insert name 可解析
 *   - 2.3.3（--pack）npm pack --dry-run 通过
 *   - 6.1 scripts 门禁（SHOULD 级）
 *
 * 注意：这是静态门禁，不是完整评审。§3/§4/§5 的生命周期、HTTP、
 * 持久化、XSS 等仍需人工按 STANDARD.md 附录 B 审查。
 */
import { access, readFile, stat, readdir } from 'node:fs/promises'
import { dirname, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'

const execFileP = promisify(execFile)
const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')

// ---------- 参数解析 ----------
function parseArgs(argv) {
  const args = { dir: process.cwd(), pack: false, json: false, version: false, koishi: false, compat: false }
  for (const a of argv) {
    if (a === '--pack') args.pack = true
    else if (a === '--koishi') args.koishi = true
    else if (a === '--compat') args.compat = true
    else if (a === '--json') args.json = true
    else if (a === '--version' || a === '-v') args.version = true
    else if (a === '--help' || a === '-h') args.help = true
    else if (!a.startsWith('-')) args.dir = resolve(a)
    else {
      process.stderr.write(`未知参数: ${a}\n`)
      process.exit(2)
    }
  }
  return args
}

// ---------- 结果收集 ----------
const results = []
/** 识别 koishi 插件：包名 koishi-plugin-*（含 scope）或 peerDependencies 含 koishi。 */
function isKoishiPlugin(pkg) {
  if (!pkg || typeof pkg.name !== 'string') return false
  if (/^(?:@[^/]+\/)?koishi-plugin-/.test(pkg.name)) return true
  return Boolean(pkg.peerDependencies && pkg.peerDependencies.koishi)
}

/** 扫描 koishi 插件源码的安全/生命周期红线（WARN 级，平台不背书提示；真正的隔离交给 fail-soft）。 */
async function scanKoishiRisks(dir, pkg) {
  const risks = []
  const seen = new Set()
  const files = []
  if (pkg.main) files.push(resolve(dir, pkg.main))
  try {
    const entries = await readdir(resolve(dir, 'lib'))
    for (const e of entries) if (e.endsWith('.js') || e.endsWith('.cjs')) files.push(resolve(dir, 'lib', e))
  } catch { /* 无 lib 目录 */ }
  const patterns = [
    { re: /\beval\s*\(/, label: 'eval(' },
    { re: /new\s+Function\s*\(/, label: 'new Function(' },
    { re: /child_process|execFile(?:Sync)?\s*\(|spawn(?:Sync)?\s*\(/, label: '子进程命令执行' },
    { re: /process\.env/, label: '读取 process.env（密钥/凭据暴露风险）' },
    { re: /writeFile(?:Sync)?\s*\(|appendFile(?:Sync)?\s*\(|unlink(?:Sync)?\s*\(/, label: '文件系统写入/删除' },
  ]
  for (const f of files) {
    let text
    try { text = await readFile(f, 'utf8') } catch { continue }
    for (const { re, label } of patterns) {
      if (re.test(text) && !seen.has(label)) {
        seen.add(label)
        risks.push(`${label}（${f.slice(dir.length + 1)}）`)
      }
    }
  }
  return risks
}

// ═══════════════════ COMPAT 版本兼容层静态识别（F2，--compat）═══════════════════
// 只做"改名/别名"级识别（不做语义转译），判级 COMPAT/Compliant/Not-Compliant，
// 供市场打 COMPAT 徽章与 fail-soft 联动。注册表随 DSH 版本演进（维护组维护）。
const COMPAT_REGISTRY = {
  forDSH: '0.1.0-rc.6',
  /** 当前 DSH 版本的有效服务 key（原生服务，非未知）。 */
  currentServices: ['tools', 'llm', 'subagents', 'systemPrompt', 'agents', 'webServer', 'workspaceRegistry', 'compaction', 'commands', 'agentDefaultModel', 'mneme', 'pluginHub'],
  serviceAliases: {
    webServer: ['httpServer'],
    workspaceRegistry: ['workspace'],
    compaction: ['compact'],
  },
  packageAliases: {
    '@deepseek-ai/dsh-web-server': ['@deepseek-ai/dsh-host-webserver'],
  },
}

/** 最小 semver 解析（支持 ^x.y.z / ~x.y.z / >=x <y / x.y.z / x / *）。 */
function parseVer(s) {
  const m = /^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:[-+].+)?$/.exec(String(s).trim())
  if (!m) return null
  return { maj: +m[1], min: m[2] ? +m[2] : 0, pat: m[3] ? +m[3] : 0 }
}
function cmpVer(a, b) {
  if (!a || !b) return 0
  return (a.maj - b.maj) || (a.min - b.min) || (a.pat - b.pat)
}
/** 单段范围满足（支持 ^ / ~ / >= / > / <= / < / 精确 / *）。 */
function satSingle(range, v) {
  const r = range.trim()
  if (!r || r === '*' || r === 'x' || r === 'X') return true
  const m = /^(\^|~|>=|<=|>|<|=)?\s*v?(\d+|\*)(?:\.(\d+|\*))?(?:\.(\d+|\*))?$/.exec(r)
  if (!m) return true // 解析不了 → 不误判（保守放行）
  const op = m[1] || '='
  const mk = (a, b, c) => ({ maj: a === '*' ? 0 : +a, min: b === '*' || b === undefined ? 0 : +b, pat: c === '*' || c === undefined ? 0 : +c })
  const base = mk(m[2], m[3], m[4])
  const any = m[2] === '*' || m[3] === '*' || m[4] === '*'
  if (op === '^') {
    if (any) return true
    const lower = mk(m[2], m[3] ?? 0, 0)
    const upper = mk(m[2] === '0' ? 0 : +m[2] + 1, 0, 0)
    return cmpVer(v, lower) >= 0 && cmpVer(v, upper) < 0
  }
  if (op === '~') return cmpVer(v, base) >= 0 && cmpVer(v, { maj: base.maj, min: base.min + 1, pat: 0 }) < 0
  if (op === '>') return cmpVer(v, base) > 0
  if (op === '>=') return cmpVer(v, base) >= 0
  if (op === '<') return cmpVer(v, base) < 0
  if (op === '<=') return cmpVer(v, base) <= 0
  if (op === '=') return any ? true : cmpVer(v, base) === 0
  return true
}
/** 范围满足（支持 || 与空格分段）。 */
function semverSatisfies(version, range) {
  const v = parseVer(version)
  if (!v) return false
  for (const part of String(range).split('||')) {
    if (part.split(/\s+/).filter(Boolean).every((seg) => satSingle(seg, v))) return true
  }
  return false
}

/** 静态扫描插件的 COMPAT 相关引用（peerDep 范围 / 服务 key / 旧包名）。 */
async function scanCompat(dir, pkg) {
  const referencedKeys = new Set()
  const propertyKeys = new Set()
  const oldPackages = new Set()
  const rangeIssues = []
  // 1) peerDependencies 中 @deepseek-ai/* 的范围 + 旧包名识别
  const peers = pkg.peerDependencies || {}
  const oldPkgList = Object.values(COMPAT_REGISTRY.packageAliases).flat()
  for (const [k, range] of Object.entries(peers)) {
    if (!k.startsWith('@deepseek-ai/')) continue
    if (!semverSatisfies(COMPAT_REGISTRY.forDSH, range)) rangeIssues.push(`${k}@${range}`)
    if (oldPkgList.includes(k)) oldPackages.add(k) // peerDep 声明了旧包名
  }
  // 2) 服务 key / 包名引用扫描（main + lib 下 js/cjs/mjs/ts）
  const files = []
  if (pkg.main) files.push(resolve(dir, pkg.main))
  try {
    for (const e of await readdir(resolve(dir, 'lib'))) if (/\.(js|cjs|mjs|ts)$/.test(e)) files.push(resolve(dir, 'lib', e))
  } catch { /* 无 lib */ }
  const allOldKeys = new Set(Object.values(COMPAT_REGISTRY.serviceAliases).flat())
  const allNewKeys = Object.keys(COMPAT_REGISTRY.serviceAliases)
  const knownRuntime = new Set(['get', 'logger', 'on', 'emit', 'provide', 'effect', 'inject', 'plugin', 'registry', 'root', 'model', 'config', 'runtime', 'baseUrl', 'baseDir', 'slots', 'agents', 'commands', 'name', 'server', 'ref', 'app', 'state'])
  for (const f of files) {
    let t
    try { t = await readFile(f, 'utf8') } catch { continue }
    // 双通道：ctx.get('x') / inject 声明 = 显式服务获取（严格）；ctx.x 属性访问 = 弱信号（提示）
    for (const m of t.matchAll(/ctx\.get\(['"]([a-zA-Z]+)['"]\)/g)) {
      if (m[1] && !referencedKeys.has(m[1])) referencedKeys.add(m[1])
    }
    for (const m of t.matchAll(/ctx\.([a-zA-Z]+)\b/g)) {
      const k = m[1]
      if (k && !knownRuntime.has(k) && !propertyKeys.has(k)) propertyKeys.add(k)
    }
    for (const m of t.matchAll(/from\s+['"](@deepseek-ai\/[^'"]+)['"]|require\(['"](@deepseek-ai\/[^'"]+)['"]\)/g)) {
      const p = m[1] ?? m[2]
      if (Object.values(COMPAT_REGISTRY.packageAliases).flat().includes(p)) oldPackages.add(p)
    }
  }
  // inject 声明（DSH 插件依赖的服务列表）也视为显式服务获取
  for (const k of Array.isArray(pkg.inject) ? pkg.inject : []) {
    if (typeof k === 'string') referencedKeys.add(k)
  }
  return { referencedKeys: [...referencedKeys], propertyKeys: [...propertyKeys], oldPackages: [...oldPackages], rangeIssues, allOldKeys, allNewKeys, currentServices: COMPAT_REGISTRY.currentServices }
}

/** 判级：显式未知服务 key → Not-Compliant；命中改名/旧包名/范围不满足 → COMPAT；否则 Compliant。 */
function judgeCompat(s) {
  const isUnknown = (k) => !s.currentServices.includes(k) && !s.allNewKeys.includes(k) && !s.allOldKeys.has(k)
  const unknown = s.referencedKeys.filter(isUnknown)
  const propertyUnknown = s.propertyKeys.filter(isUnknown)
  if (unknown.length > 0) return { level: 'Not-Compliant', unknown, propertyUnknown }
  const hitsOld = [...s.referencedKeys, ...s.propertyKeys].filter((k) => s.allOldKeys.has(k))
  const compat = s.rangeIssues.length > 0 || hitsOld.length > 0 || s.oldPackages.length > 0
  return { level: compat ? 'COMPAT' : 'Compliant', unknown, propertyUnknown, hitsOld }
}

function record(level, clause, message) {
  results.push({ level, clause, message })
}

// ---------- 文件存在性 ----------
async function exists(p) {
  try {
    await access(p)
    return true
  } catch {
    return false
  }
}

// ---------- exports 路径展开 ----------
function collectExportPaths(exports) {
  const paths = []
  if (typeof exports === 'string') {
    paths.push(exports)
    return paths
  }
  if (exports && typeof exports === 'object') {
    for (const [key, value] of Object.entries(exports)) {
      if (value && typeof value === 'object') {
        for (const v of Object.values(value)) {
          if (typeof v === 'string') paths.push({ key, value: v })
        }
      } else if (typeof value === 'string') {
        paths.push({ key, value })
      }
    }
  }
  return paths
}

// ---------- 提取源码导出的 name ----------
async function extractExportName(dir, pkg) {
  const candidates = [resolve(dir, 'src/index.ts'), resolve(dir, 'src/index.js'), resolve(dir, pkg.main || 'lib/index.js')]
  for (const file of candidates) {
    if (!(await exists(file))) continue
    const text = await readFile(file, 'utf8')
    const m = text.match(/export\s+const\s+name\s*=\s*['"]([^'"]+)['"]/)
    if (m) return { file, name: m[1] }
  }
  return null
}

// ---------- 提取 client wrapper id ----------
async function extractClientId(dir, pkg) {
  const file = resolve(dir, 'lib/client.js')
  if (!(await exists(file))) return null
  const text = await readFile(file, 'utf8')
  const m = text.match(/__ModuleLoader__\.load\(\s*\{\s*id\s*:\s*['"]([^'"]+)['"]/)
  if (m) return { file, id: m[1] }
  return null
}

// ---------- 极简 patch YAML 解析（规范要求的形状） ----------
function parsePatch(profileText) {
  const ids = []
  const names = []
  const lines = profileText.split('\n')
  let inInsert = false
  for (const raw of lines) {
    const line = raw.replace(/\r$/, '')
    const trimmed = line.trim()
    if (/^-\s*insert\s*:$/.test(trimmed)) {
      inInsert = true
      continue
    }
    if (inInsert && trimmed === '') continue
    const idM = trimmed.match(/^-\s*id:\s*['"]?([^'"\s]+)['"]?$/)
    if (idM) {
      ids.push(idM[1])
      continue
    }
    const nameM = trimmed.match(/^name:\s*['"]?([^'"\s]+)['"]?$/)
    if (nameM && inInsert) names.push(nameM[1])
  }
  return { ids, names }
}

// ---------- 主校验 ----------
async function main() {
  const args = parseArgs(process.argv.slice(2))
  if (args.version) {
    process.stdout.write('DSH Plugin Standard checker 2.2.1\n')
    process.exit(0)
  }
  if (args.help) {
    process.stdout.write(
      'DSH 插件规范合规校验器\n\n' +
      '用法:\n' +
      '  node scripts/verify-plugin.mjs [插件目录] [--pack] [--koishi] [--compat] [--json] [--version]\n\n' +
      '退出码:\n' +
      '  0 = 无 MUST 违规\n' +
      '  1 = 存在 MUST 违规\n' +
      '  2 = 目录不可用或参数错误\n',
    )
    process.exit(0)
  }

  const dir = args.dir
  const pkgFile = resolve(dir, 'package.json')
  if (!(await exists(pkgFile))) {
    if (!args.json) process.stderr.write(`[ERROR] 未找到 ${pkgFile}（${dir} 不是插件目录？）\n`)
    process.exit(2)
  }

  let pkg
  try {
    pkg = JSON.parse(await readFile(pkgFile, 'utf8'))
  } catch (error) {
    if (!args.json) process.stderr.write(`[ERROR] package.json 解析失败: ${error.message}\n`)
    process.exit(2)
  }

  const hasBundle = Boolean(pkg.dsh?.bundle?.patch)
  const hasClientDecl = Boolean(pkg.dsh?.client)
  const hasClientExport = Boolean(pkg.exports && (pkg.exports['./client'] || (typeof pkg.exports === 'string' && false)))
  let patchIds = []

  // koishi 兼容模式：--koishi 强制，或自动识别 koishi 插件即启用（生态桥 F1）
  const koishiMode = args.koishi || isKoishiPlugin(pkg)
  if (koishiMode && !args.koishi) {
    record('INFO', 'KO0', '自动识别为 koishi 插件，已启用 koishi 兼容校验模式（门槛级 Compliant，平台不背书）')
  }

  // ---- 2.1.1 type: module ----
  if (koishiMode) {
    record('INFO', '2.1.1', 'koishi 兼容模式：跳过 type:module 要求（CJS/默认导出由 cordis loader 归一化）')
  } else if (args.compat) {
    record('INFO', '2.1.1', 'COMPAT 识别模式：跳过 type:module 要求（旧版插件可能 CJS，由 COMPAT 判级决定）')
  } else if (pkg.type === 'module') {
    record('PASS', '2.1.1', 'type: module')
  } else {
    record('FAIL', '2.1.1', `type 应为 "module"，当前 ${JSON.stringify(pkg.type)}`)
  }

  // ---- 2.1.2 main/types/exports 指向真实产物 ----
  if (pkg.main) {
    const p = resolve(dir, pkg.main)
    if (await exists(p)) record('PASS', '2.1.2', `main 存在: ${pkg.main}`)
    else record('FAIL', '2.1.2', `main 指向不存在的文件: ${pkg.main}`)
  }
  if (pkg.types) {
    const p = resolve(dir, pkg.types)
    if (await exists(p)) record('PASS', '2.1.2', `types 存在: ${pkg.types}`)
    else record('FAIL', '2.1.2', `types 指向不存在的文件: ${pkg.types}`)
  }
  if (pkg.exports) {
    const bad = []
    for (const { key, value } of collectExportPaths(pkg.exports)) {
      if (key === './package.json' || value === './package.json') continue
      const p = resolve(dir, value)
      if (!(await exists(p))) bad.push(`${key} -> ${value}`)
    }
    if (bad.length === 0) record('PASS', '2.1.2', 'exports 全部指向真实文件')
    else record('FAIL', '2.1.2', `exports 指向不存在的文件: ${bad.join('; ')}`)
  } else {
    record('WARN', '2.1.2', '未声明 exports（非 bundle 形态可不声明，如 agent preset）')
  }

  // ---- 2.1.3 client 声明与 ./client 同时出现 ----
  if (koishiMode) {
    record('INFO', '2.1.3', 'koishi 兼容模式：跳过 client 声明要求（koishi 生态无 DSH client）')
  } else if (hasClientDecl && !hasClientExport) {
    record('FAIL', '2.1.3', '声明了 dsh.client 但 exports 缺少 "./client"')
  } else if (!hasClientDecl && hasClientExport) {
    record('FAIL', '2.1.3', '存在 exports["./client"] 但缺少 dsh.client 声明')
  } else if (hasClientDecl) {
    if (pkg.dsh.client.platform === 'web') {
      record('PASS', '2.1.3', 'client 声明与 ./client 成对，platform=web')
    } else {
      record('FAIL', '2.1.3', `dsh.client.platform 应为 "web"，当前 ${JSON.stringify(pkg.dsh.client.platform)}`)
    }
    if (!Array.isArray(pkg.dsh.client.inject) || pkg.dsh.client.inject.length === 0) {
      record('FAIL', '2.1.5', 'dsh.client.inject 应为非空包名数组（写包名，不是服务名）')
    } else {
      const suspicious = pkg.dsh.client.inject.filter((s) => !/^@[^/]+\/[^/]+$/.test(s) && s.indexOf('.') === -1)
      if (suspicious.length > 0) {
        record('WARN', '2.1.5', `inject 中有疑似服务名/非包名: ${suspicious.join(', ')}`)
      }
    }
  } else {
    record('INFO', '2.1.3', 'host-only 插件（无 client 声明）')
  }

  // ---- 2.1.4 dsh.bundle.patch ----
  if (koishiMode) {
    record('INFO', '2.1.4', 'koishi 兼容模式：无 bundle patch（由适配层 bundle 包装装配）')
  } else if (hasBundle) {
    const patchRel = pkg.dsh.bundle.patch
    const patchFile = resolve(dir, patchRel)
    if (await exists(patchFile)) {
      record('PASS', '2.1.4', `dsh.bundle.patch 存在: ${patchRel}`)
    } else {
      record('FAIL', '2.1.4', `dsh.bundle.patch 指向不存在的文件: ${patchRel}`)
    }
  } else {
    record('INFO', '2.1.4', '非 bundle 包（普通依赖/preset 形态）')
  }

  // ---- 2.2.1/2.2.4 patch 契约 + 2.1.7 name 一致性 ----
  if (!koishiMode && hasBundle) {
    const patchRel = pkg.dsh.bundle.patch
    const patchFile = resolve(dir, patchRel)
    if (await exists(patchFile)) {
      const text = await readFile(patchFile, 'utf8')
      const { ids, names } = parsePatch(text)
      patchIds = ids
      if (ids.length === 0) {
        record('FAIL', '2.2.1', 'patch 未解析出任何 insert id（应为顶层数组 + - id: 行）')
      } else {
        const uniq = new Set(ids)
        if (uniq.size === ids.length) record('PASS', '2.2.1', `patch insert id 唯一（${ids.length} 个）`)
        else record('FAIL', '2.2.1', `patch insert id 重复: ${ids.filter((id, i) => ids.indexOf(id) !== i).join(', ')}`)
        // 2.2.4：insert name 必须可解析——等于 bundle 包名，或为聚合 bundle 形态下
        // 被本包 dependencies/peerDependencies 引用的子包名。
        const declared = new Set([...Object.keys(pkg.dependencies || {}), ...Object.keys(pkg.peerDependencies || {})])
        const bad = names.filter((n) => n !== pkg.name && !declared.has(n))
        if (names.length === 0) {
          record('WARN', '2.2.1', 'patch 未解析出 insert name（应等于包名或被依赖的子包名）')
        } else if (bad.length === 0) {
          const resolved = names.every((n) => n === pkg.name) ? '全部等于包名' : '为被依赖的子包名（聚合 bundle）'
          record('PASS', '2.2.4', `patch insert name 可解析（${resolved}）: ${[...new Set(names)].join(', ')}`)
        } else {
          record('FAIL', '2.2.4', `patch insert name 不可解析: ${bad.join(', ')}（应为包名 ${pkg.name} 或 dependencies 中的子包名）`)
        }
      }
    }
  }

  // ---- 2.1.7 源码 export const name ----
  // 官方契约：源码导出 name 是 Cordis 插件标识（可为短名，如 'agent-teams'），
  // 不必等于包名；但若带 scope（含 '/'）就必须等于包名，禁止旧 scope 残留。
  const srcName = await extractExportName(dir, pkg)
  if (srcName) {
    if (srcName.name.includes('/')) {
      if (srcName.name === pkg.name) {
        record('PASS', '2.1.7', `源码导出 name 带 scope 且等于包名: ${srcName.name}`)
      } else {
        record('FAIL', '2.1.7', `源码导出 name 带 scope 但与包名不一致: ${srcName.file} 导出 ${JSON.stringify(srcName.name)}，包名 ${JSON.stringify(pkg.name)}（旧 scope 残留，必须对齐）`)
      }
    } else {
      record('PASS', '2.1.7', `源码导出 name 为短名（Cordis 插件标识）: ${srcName.name}`)
      if (patchIds.length > 0 && patchIds.every((id) => id !== srcName.name)) {
        record('WARN', '2.1.7', `源码导出 name 与 patch insert id 不一致（${srcName.name} vs ${patchIds.join(', ')}），建议保持一致避免歧义`)
      }
    }
  } else {
    record('INFO', '2.1.7', '未找到 export const name（仅 client 或非标准形态时忽略）')
  }

  // ---- 2.1.7 client wrapper id ----
  if (hasClientExport) {
    const clientId = await extractClientId(dir, pkg)
    if (clientId) {
      if (clientId.id === pkg.name) {
        record('PASS', '2.1.7', `client wrapper id 一致: ${clientId.id}`)
      } else {
        record('FAIL', '2.1.7', `client wrapper id 与包名不一致: ${clientId.file} 中 ${JSON.stringify(clientId.id)}，包名 ${JSON.stringify(pkg.name)}`)
      }
    } else {
      record('WARN', '2.1.7', 'lib/client.js 未找到 window.__ModuleLoader__.load id（可能未构建）')
    }
  }

  // ---- 2.1.6 @deepseek-ai 不得进 dependencies ----
  const deps = pkg.dependencies || {}
  const forbidden = Object.keys(deps).filter((d) => d.startsWith('@deepseek-ai/'))
  if (forbidden.length === 0) {
    record('PASS', '2.1.6', 'dependencies 无 @deepseek-ai/*（共享运行时应走 peerDependencies）')
  } else {
    record('FAIL', '2.1.6', `dependencies 含共享运行时 @deepseek-ai/*: ${forbidden.join(', ')}（应移到 peerDependencies）`)
  }

  // ---- koishi 兼容检查集（KO1/KO2/KO3）----
  if (koishiMode) {
    const peers = pkg.peerDependencies || {}
    if (peers.koishi) {
      record('PASS', 'KO1', `声明 peerDependencies.koishi: ${peers.koishi}`)
    } else {
      record('FAIL', 'KO1', 'koishi 插件必须声明 peerDependencies.koishi（shim 解析依赖它，无则无法桥接）')
    }
    if (pkg.main) {
      const p = resolve(dir, pkg.main)
      if (await exists(p)) record('PASS', 'KO2', `main 存在: ${pkg.main}`)
      else record('FAIL', 'KO2', `main 指向不存在的文件: ${pkg.main}`)
    } else {
      record('FAIL', 'KO2', 'koishi 插件必须声明 main（CJS 产物入口）')
    }
    const risks = await scanKoishiRisks(dir, pkg)
    if (risks.length === 0) {
      record('PASS', 'KO3', '未发现高危模式（eval / new Function / 任意命令执行）')
    } else {
      for (const r of risks) record('WARN', 'KO3', `安全红线提示: ${r}（平台不背书，安装需谨慎；隔离交给 fail-soft）`)
    }
    record('INFO', 'KO4', 'koishi 兼容 = 门槛级 Compliant（结构合规 + shim 覆盖），非 DSH 原生合规；按特殊通道 Experimental 上架')
  }

  // ---- COMPAT 版本兼容层静态识别（--compat / F2）----
  let compatLevel = null
  if (args.compat) {
    const s = await scanCompat(dir, pkg)
    const judged = judgeCompat(s)
    compatLevel = judged.level
    if (s.rangeIssues.length === 0) {
      record('PASS', 'CP1', 'peerDependencies @deepseek-ai/* 范围覆盖当前 DSH 版本')
    } else {
      record('WARN', 'CP1', `peerDependencies 范围不覆盖当前 DSH ${COMPAT_REGISTRY.forDSH}: ${s.rangeIssues.join(', ')}`)
    }
    if (judged.unknown.length > 0) {
      record('FAIL', 'CP2', `引用未知服务 key（不可 shim，语义缺失）: ${judged.unknown.join(', ')}`)
    } else if (judged.propertyUnknown.length > 0) {
      record('WARN', 'CP2', `引用疑似 ctx 属性（忽略，非服务依赖）: ${judged.propertyUnknown.join(', ')}`)
    } else if (judged.hitsOld.length > 0) {
      record('WARN', 'CP2', `引用旧服务 key（可 COMPAT 别名重定向）: ${judged.hitsOld.join(', ')}`)
    } else {
      record('PASS', 'CP2', '服务 key 引用无未知/旧名')
    }
    if (s.oldPackages.length > 0) {
      record('WARN', 'CP3', `引用旧包名（可 COMPAT 包名重定向）: ${s.oldPackages.join(', ')}`)
    } else {
      record('PASS', 'CP3', '无旧包名引用')
    }
    record('INFO', 'CP4', `COMPAT 判级: ${compatLevel}${compatLevel === 'Not-Compliant' ? '（不可 shim，需拒装或特殊通道）' : compatLevel === 'COMPAT' ? '（未适配当前版本，由 shim 托底运行 + COMPAT 徽章）' : '（原生适配当前版本）'}`)
  }

  // ---- 6.1 scripts 门禁（SHOULD） ----
  const scripts = pkg.scripts || {}
  const required = ['typecheck', 'build', 'test', 'verify', 'pack']
  const missing = required.filter((s) => !scripts[s] && !scripts[`pack:check`])
  if (missing.length === 0) {
    record('PASS', '6.1', 'scripts 覆盖 typecheck/build/test/verify/pack')
  } else {
    record('WARN', '6.1', `scripts 缺失（SHOULD）: ${missing.join(', ')}`)
  }

  // ---- 2.1.8 engines（SHOULD） ----
  if (pkg.engines?.node) {
    record('PASS', '2.1.8', `engines.node: ${pkg.engines.node}`)
  } else {
    record('WARN', '2.1.8', '未声明 engines.node（SHOULD）')
  }

  // ---- 2.1.9 files（SHOULD） ----
  const files = pkg.files
  if (Array.isArray(files)) {
    const essential = ['lib', 'cordis.patch.yml', 'README.md']
    const missingFiles = essential.filter((f) => !files.some((x) => x === f || x.startsWith(f + '/')))
    if (missingFiles.length === 0) {
      record('PASS', '2.1.9', 'files 覆盖 lib/cordis.patch.yml/README.md')
    } else {
      record('WARN', '2.1.9', `files 缺少: ${missingFiles.join(', ')}（SHOULD）`)
    }
  } else {
    record('INFO', '2.1.9', '未声明 files（非发布包可忽略）')
  }

  // ---- 2.3.3 --pack ----
  if (args.pack) {
    try {
      // Windows 下 npm 是 npm.cmd：execFile 需 shell（Node ≥18.20 对 .cmd 强制，CVE-2024-27980）——本仓库补丁
      const { stdout } = await execFileP('npm', ['pack', '--dry-run', '--json'], { cwd: dir, timeout: 60_000, shell: process.platform === 'win32' })
      let list = []
      try {
        list = JSON.parse(stdout)
      } catch {
        list = []
      }
      const files2 = Array.isArray(list) && list[0]?.files ? list[0].files : []
      if (files2.length > 0) {
        record('PASS', '2.3.3', `npm pack --dry-run 通过（${files2.length} 个文件待发布）`)
      } else {
        record('WARN', '2.3.3', 'npm pack --dry-run 通过但未解析到文件列表')
      }
    } catch (error) {
      record('FAIL', '2.3.3', `npm pack --dry-run 失败: ${error.message}`)
    }
  }

  // ---- 汇总 ----
  const fails = results.filter((r) => r.level === 'FAIL')
  const warns = results.filter((r) => r.level === 'WARN')
  const infos = results.filter((r) => r.level === 'INFO')

  if (args.json) {
    const out = { dir, package: pkg.name, version: pkg.version, results, summary: { fail: fails.length, warn: warns.length, info: infos.length } }
    if (args.compat) out.compat = compatLevel
    process.stdout.write(JSON.stringify(out, null, 2) + '\n')
  } else {
    process.stdout.write(`\nDSH 插件规范合规校验 — ${pkg.name}@${pkg.version}（${dir}）\n`)
    process.stdout.write(`${'-'.repeat(72)}\n`)
    for (const r of results) {
      process.stdout.write(`${r.level.padEnd(5)} [${r.clause}] ${r.message}\n`)
    }
    process.stdout.write(`${'-'.repeat(72)}\n`)
    process.stdout.write(`汇总: ${fails.length} FAIL / ${warns.length} WARN / ${infos.length} INFO\n`)
  }

  process.exit(fails.length > 0 ? 1 : 0)
}

main().catch((error) => {
  process.stderr.write(`[ERROR] verify-plugin 运行失败: ${error.stack || error.message}\n`)
  process.exit(2)
})
