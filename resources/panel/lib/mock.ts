/**
 * 仅开发环境使用的假数据（npm run dev 与 vitest）。
 * api.ts 只在 import.meta.env.DEV 为 true 时调用 mockRequest，生产构建会把本模块整个摇掉。
 * 样例数据；IP 全部取自文档保留段（192.0.2.0/24、198.51.100.0/24、203.0.113.0/24、2001:db8::/32）。
 */
import type {
  AllowEntry,
  AuditEntry,
  Ban,
  Incident,
  IncidentDetail,
  Method,
  Query,
  RawResponse,
  RuleRef,
  Settings,
} from "./api"
import { MODES, RULE_ACTIONS } from "./format"

const MIN = 60_000
const now = () => Date.now()
const ago = (minutes: number) => new Date(now() - minutes * MIN).toISOString()
const later = (minutes: number) => new Date(now() + minutes * MIN).toISOString()

const HISTORY_LIMIT = 500

const R: Record<string, RuleRef> = {
  "not-found-scan": { id: "not-found-scan", name: "404 扫描" },
  "sensitive-path": { id: "sensitive-path", name: "敏感文件探测" },
  "scanner-agent": { id: "scanner-agent", name: "扫描器特征" },
  "attack-pattern": { id: "attack-pattern", name: "攻击特征" },
  "known-exploit": { id: "known-exploit", name: "已知漏洞探测" },
  // 宿主登记的自定义规则：规则清单是动态的，界面不能假设恰好五条
  "login-burst": { id: "login-burst", name: "登录爆破" },
}

function incident(p: Partial<Incident> & Pick<Incident, "id" | "visitor" | "disposition">, minutesAgo: number): Incident {
  return {
    time: ago(minutesAgo),
    region: null,
    rule: null,
    source: "auto",
    count: null,
    observe: false,
    operator: null,
    note: null,
    ...p,
  }
}

// 惰性创建：模块顶层没有任何调用，生产构建才能把整个模块摇掉。
function createState() {
  return {
  incidents: [
    incident({ id: "BAN-20261106-7K2M9Q", visitor: "203.0.113.47", region: "NL", rule: R["sensitive-path"], count: 3, disposition: "banned" }, 6),
    incident({ id: "BAN-20261106-4H8T2P", visitor: "198.51.100.23", region: "US", rule: R["known-exploit"], count: 1, disposition: "banned" }, 10),
    incident({ id: "BAN-20261106-9C3N5W", visitor: "192.0.2.60", region: "SG", rule: R["not-found-scan"], count: 10, disposition: "exempted" }, 13),
    incident({ id: "BAN-20261106-2B6R8X", visitor: "2001:db8:4c2:91::/64", region: "DE", rule: R["not-found-scan"], count: 10, disposition: "banned" }, 17),
    incident({ id: "BAN-20261106-6D1K4M", visitor: "198.51.100.77", region: "US", rule: R["scanner-agent"], count: 2, disposition: "banned" }, 28),
    incident({ id: "BAN-20261106-3F7J9L", visitor: "192.0.2.118", region: "SG", source: "manual", disposition: "banned", operator: "admin", note: "反复用错误签名请求代付接口" }, 98),
    incident({ id: "BAN-20261106-8G2Q6Z", visitor: "203.0.113.150", region: "FR", rule: R["sensitive-path"], count: 3, disposition: "unbanned" }, 186),
    incident({ id: "BAN-20261106-5A9V3Y", visitor: "198.51.100.201", region: "BR", rule: R["attack-pattern"], count: 5, disposition: "expired" }, 294),
    incident({ id: "BAN-20261106-1E4U7S", visitor: "192.0.2.33", region: "JP", rule: R["attack-pattern"], count: 5, disposition: "recorded", observe: true }, 420),
    incident({ id: "BAN-20261106-0P5L2K", visitor: "198.51.100.90", region: null, rule: R["login-burst"], count: 8, disposition: "recorded" }, 510),
  ] as Incident[],

  bans: [
    { visitor: "203.0.113.47", visitor_note: null, region: "NL", rule: R["sensitive-path"], source: "auto", reason: "10 分钟内 3 个不同地址", banned_at: ago(6), unban_at: later(114), remaining_seconds: 6840, total_seconds: 7200, blocked: 37, offense: 1, incident_id: "BAN-20261106-7K2M9Q", operator: null, note: null },
    { visitor: "198.51.100.23", visitor_note: null, region: "US", rule: R["known-exploit"], source: "auto", reason: "命中 1 次即封", banned_at: ago(10), unban_at: later(110), remaining_seconds: 6600, total_seconds: 7200, blocked: 12, offense: 1, incident_id: "BAN-20261106-4H8T2P", operator: null, note: null },
    { visitor: "2001:db8:4c2:91::/64", visitor_note: "IPv6 按 64 位网段封禁", region: "DE", rule: R["not-found-scan"], source: "auto", reason: "5 分钟内 10 个不同地址", banned_at: ago(17), unban_at: later(13), remaining_seconds: 781, total_seconds: 1800, blocked: 5, offense: 1, incident_id: "BAN-20261106-2B6R8X", operator: null, note: null },
    { visitor: "192.0.2.118", visitor_note: null, region: "SG", rule: null, source: "manual", reason: "由 admin 操作：反复用错误签名请求代付接口", banned_at: ago(98), unban_at: later(1342), remaining_seconds: 80520, total_seconds: 86400, blocked: 148, offense: null, incident_id: "BAN-20261106-3F7J9L", operator: "admin", note: "反复用错误签名请求代付接口" },
    { visitor: "198.51.100.77", visitor_note: null, region: "US", rule: R["scanner-agent"], source: "auto", reason: "10 分钟内 2 次", banned_at: ago(28), unban_at: later(212), remaining_seconds: 12720, total_seconds: 14400, blocked: 3, offense: 2, incident_id: "BAN-20261106-6D1K4M", operator: null, note: null },
  ] as Ban[],

  allowlist: {
    // 标签照后端 RedisAllowlistRepository::LABELS
    builtin: [
      { entry: "10.0.0.0/8", label: "内网段" },
      { entry: "172.16.0.0/12", label: "内网段" },
      { entry: "192.168.0.0/16", label: "内网段" },
      { entry: "127.0.0.0/8", label: "回环" },
      { entry: "::1", label: "回环" },
      { entry: "173.245.48.0/20", label: "Cloudflare" },
      { entry: "2400:cb00::/32", label: "Cloudflare" },
      { entry: "192.0.2.10", label: "配置文件" },
    ],
    data: [
      { entry: "203.0.113.10", note: "办公室出口", added_by: "admin", added_at: "2026-11-05T10:12:00+08:00" },
      { entry: "198.51.100.0/28", note: "监控探针", added_by: "admin", added_at: "2026-11-05T10:15:00+08:00" },
      { entry: "192.0.2.5", note: null, added_by: "admin", added_at: "2026-11-06T09:40:00+08:00" },
    ] as AllowEntry[],
  },

  settings: {
    enabled: true,
    mode: "block",
    rules: [
      { id: "not-found-scan", name: "404 扫描", description: "请求了程序里没有的地址。同一个地址重复请求只算一次。", action: "ban", window_minutes: 5, count: 10, ban_minutes: 30, hits_24h: 742, count_mode: "distinct" },
      { id: "sensitive-path", name: "敏感文件探测", description: "环境文件、版本库目录、备份与数据库导出、后台入口、后门文件名，以及 Laravel 的日志目录和调试面板。", action: "ban", window_minutes: 10, count: 3, ban_minutes: 120, hits_24h: 301, count_mode: "distinct" },
      { id: "scanner-agent", name: "扫描器特征", description: "浏览器标识属于已知的扫描器。", action: "ban", window_minutes: 10, count: 2, ban_minutes: 120, hits_24h: 87, count_mode: "each" },
      { id: "attack-pattern", name: "攻击特征", description: "地址或参数里出现 SQL 注入、跨站、路径穿越、命令执行，或使用异常的请求方法。", action: "ban", window_minutes: 1, count: 5, ban_minutes: 60, hits_24h: 118, count_mode: "distinct" },
      { id: "known-exploit", name: "已知漏洞探测", description: "请求了已知漏洞的利用地址，或请求里带 Log4j 特征。正常访客不会请求，所以命中一次就封。", action: "ban", window_minutes: 10, count: 1, ban_minutes: 120, hits_24h: 93, count_mode: "distinct" },
      { id: "login-burst", name: "登录爆破", description: "宿主程序登记的自定义规则：同一访客短时间内多次登录失败。", action: "observe", window_minutes: 5, count: 8, ban_minutes: 60, hits_24h: 12, count_mode: "each" },
    ],
    repeat: { enabled: true, factor: 2, max_days: 7, keep_days: 7 },
    response: { status: 403, message: "检测到来自你的地址的异常访问，相关行为已被记录，请立即停止。如属误判，请把事件编号发给客服。", show_ip: true, show_incident: true, show_time: true },
    limits: { window_minutes: [1, 1440], count: [1, 100], ban_minutes: [1, 43200], factor: [2, 10], max_days: [1, 30], keep_days: [1, 30], statuses: [403, 429, 404], message: [1, 500] },
    updated_by: "admin",
    updated_at: ago(60 * 22),
  } as Settings,

  audit: [
    { time: ago(98), operator: "admin", action: "ban", target: "192.0.2.118", detail: "封 24 小时。备注：反复用错误签名请求代付接口", via: "panel" },
    { time: ago(170), operator: "console", action: "unban", target: "203.0.113.150", detail: "提前解除，当时还剩 12 分钟", via: "console" },
    { time: ago(270), operator: "admin", action: "allow_add", target: "192.0.2.5", detail: "加入白名单", via: "panel" },
    { time: ago(60 * 22), operator: "admin", action: "mode", target: "运行模式", detail: "由「观察」改为「拦截」", via: "panel" },
    { time: ago(60 * 22 + 15), operator: "admin", action: "settings", target: "404 扫描", detail: "封禁时长由 10 分钟改为 30 分钟", via: "panel" },
  ] as AuditEntry[],
  }
}

let current: ReturnType<typeof createState> | undefined
const db = () => (current ??= createState())

/** 测试之间重置假数据。 */
export function resetMock() {
  current = undefined
}

const ok = (data: unknown, status = 200): RawResponse => ({ status, data })
const invalid = (errors: Record<string, string[]>): RawResponse => ({ status: 422, data: { message: "提交的内容有误", errors } })
const notFound = (): RawResponse => ({ status: 404, data: { message: "记录不存在" } })

function page<T>(rows: T[], query?: Query) {
  const p = Math.max(1, Number(query?.page ?? 1))
  const per = Math.max(1, Number(query?.per_page ?? 20))
  return { data: rows.slice((p - 1) * per, p * per), total: rows.length, page: p, per_page: per, history_limit: HISTORY_LIMIT }
}

function audit(action: AuditEntry["action"], target: string, detail: string) {
  db().audit.unshift({ time: new Date().toISOString(), operator: "admin", action, target, detail, via: "panel" })
}

const IPV4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/
const looksLikeIp = (s: string) => IPV4.test(s) || (s.includes(":") && /^[0-9a-fA-F:]+$/.test(s))
const looksLikeEntry = (s: string) => {
  const [ip, bits, ...rest] = s.split("/")
  if (rest.length || !looksLikeIp(ip)) return false
  return bits === undefined || /^\d{1,3}$/.test(bits)
}

/** 与后端 Presenter::reason() 同一种写法。 */
function reason(inc: Incident): string | null {
  if (inc.source === "manual") return inc.note ? `由 ${inc.operator ?? "unknown"} 操作：${inc.note}` : `由 ${inc.operator ?? "unknown"} 操作`
  const rule = db().settings.rules.find((r) => r.id === inc.rule?.id)
  if (!rule || inc.count == null) return null
  if (inc.count === 1) return "命中 1 次即封"
  return `${rule.window_minutes} 分钟内 ${inc.count} ${rule.count_mode === "distinct" ? "个不同地址" : "次"}`
}

function detail(inc: Incident): IncidentDetail {
  const ban = db().bans.find((b) => b.visitor === inc.visitor && b.incident_id === inc.id)
  return {
    ...inc,
    reason: reason(inc),
    user_agent: inc.source === "manual" ? null : "Mozilla/5.0 zgrab/0.x",
    first_hit_at: inc.source === "manual" ? null : new Date(new Date(inc.time).getTime() - 69_000).toISOString(),
    banned_at: ban?.banned_at ?? null,
    unban_at: ban?.unban_at ?? null,
    remaining_seconds: ban?.remaining_seconds ?? null,
    ban_minutes: ban ? Math.round(ban.total_seconds / 60) : null,
    offense: inc.source === "manual" ? null : (ban?.offense ?? null),
    blocked: ban?.blocked ?? null,
    last_blocked_at: ban ? ago(1) : null,
    other_rules: inc.rule?.id === "sensitive-path" ? [{ id: "scanner-agent", name: "扫描器特征", count: 1 }] : [],
    requests:
      inc.rule?.id === "sensitive-path"
        ? [
            { time: new Date(new Date(inc.time).getTime() - 69_000).toISOString(), method: "GET", path: "/.env" },
            { time: new Date(new Date(inc.time).getTime() - 31_000).toISOString(), method: "GET", path: "/backup.zip" },
            { time: inc.time, method: "GET", path: "/storage/logs/laravel.log" },
          ]
        : inc.source === "manual"
          ? []
          : [
              // 后端对没有记下方法或地址的请求返回 null
              { time: new Date(new Date(inc.time).getTime() - 20_000).toISOString(), method: null, path: null },
              { time: inc.time, method: "GET", path: "/wp-login.php?<script>alert(1)</script>" },
            ],
  }
}

function removeBan(visitor: string) {
  const before = db().bans.length
  db().bans = db().bans.filter((b) => b.visitor !== visitor)
  db().incidents.forEach((i) => {
    if (i.visitor === visitor && i.disposition === "banned") i.disposition = "unbanned"
  })
  return before !== db().bans.length
}

function checkRange(errors: Record<string, string[]>, key: string, value: unknown, [min, max]: [number, number]) {
  if (typeof value !== "number" || !Number.isInteger(value) || value < min || value > max) errors[key] = [`可填 ${min} 到 ${max}`]
}

function route(method: Method, path: string, query?: Query, body?: unknown): RawResponse {
  const b = (body ?? {}) as Record<string, unknown>
  let m: RegExpMatchArray | null

  if (method === "GET" && path === "/overview") {
    const hours = Math.min(168, Number(query?.hours ?? 24))
    const trend = Array.from({ length: hours }, (_, i) => {
      const t = new Date(now() - (hours - 1 - i) * 3_600_000)
      t.setMinutes(0, 0, 0)
      const wave = Math.round(40 + 30 * Math.sin(i / 3) + (i % 7) * 4)
      return { hour: t.toISOString(), hits: wave, blocked: Math.round(wave / 4), bans: i % 5 === 0 ? 1 : 0 }
    })
    return ok({
      enabled: db().settings.enabled,
      mode: db().settings.mode,
      kpis: { hits: 1341, blocked: 312, repeat_offenders: 3, new_bans: 14, active_bans: db().bans.length },
      trend,
      rules: db().settings.rules.map((r) => ({ id: r.id, name: r.name, hits: r.hits_24h })).sort((a, c) => c.hits - a.hits),
      top_ips: [
        { key: "192.0.2.118", count: 214 },
        { key: "203.0.113.47", count: 96 },
        { key: "198.51.100.23", count: 71 },
        { key: "203.0.113.150", count: 58 },
        { key: "2001:db8:4c2:91::/64", count: 44 },
      ],
      top_targets: [
        { key: "/.env", count: 88 },
        { key: "/wp-login.php", count: 73 },
        { key: "/phpmyadmin/index.php", count: 41 },
        { key: "/admin/login", count: 36 },
        { key: "/backup.zip", count: 29 },
      ],
      top_regions: [
        { key: "US", count: 310 },
        { key: "NL", count: 180 },
        { key: "SG", count: 170 },
        { key: "DE", count: 90 },
        { key: "FR", count: 70 },
      ],
      recent: db().incidents.slice(0, 5),
    })
  }

  if (method === "GET" && path === "/incidents") {
    const q = String(query?.q ?? "").trim()
    const rows = db().incidents.filter(
      (i) =>
        (!query?.disposition || i.disposition === query.disposition) &&
        (!query?.rule || (query.rule === "manual" ? i.source === "manual" : i.rule?.id === query.rule)) &&
        (!q || i.visitor.includes(q) || i.id.includes(q.toUpperCase())),
    )
    return ok(page(rows, query))
  }

  if (method === "GET" && (m = path.match(/^\/incidents\/(.+)$/))) {
    const inc = db().incidents.find((i) => i.id === decodeURIComponent(m![1]))
    return inc ? ok(detail(inc)) : notFound()
  }

  if (method === "GET" && path === "/bans") {
    const q = String(query?.q ?? "").trim()
    const rows = db().bans.filter(
      (x) => (!query?.rule || (query.rule === "manual" ? x.source === "manual" : x.rule?.id === query.rule)) && (!q || x.visitor.includes(q)),
    )
    return ok({ data: rows, total: rows.length })
  }

  if (method === "POST" && path === "/bans") {
    const ip = String(b.ip ?? "").trim()
    const note = String(b.note ?? "").trim()
    const errors: Record<string, string[]> = {}
    if (!looksLikeIp(ip)) errors.ip = ["请输入一个合法的 IP 地址"]
    else if (db().allowlist.data.some((e) => e.entry === ip)) errors.ip = ["这个地址在白名单里，不能封禁"]
    checkRange(errors, "minutes", b.minutes, [1, 43200])
    if (!note) errors.note = ["请填写备注"]
    if (Object.keys(errors).length) return invalid(errors)
    const minutes = b.minutes as number
    const id = `BAN-${new Date().toISOString().slice(0, 10).replace(/-/g, "")}-${Math.random().toString(36).slice(2, 8).toUpperCase()}`
    removeBan(ip)
    const ban: Ban = { visitor: ip, visitor_note: null, region: null, rule: null, source: "manual", reason: `由 admin 操作：${note}`, banned_at: ago(0), unban_at: later(minutes), remaining_seconds: minutes * 60, total_seconds: minutes * 60, blocked: 0, offense: null, incident_id: id, operator: "admin", note }
    db().bans.unshift(ban)
    db().incidents.unshift(incident({ id, visitor: ip, source: "manual", disposition: "banned", operator: "admin", note }, 0))
    audit("ban", ip, `封 ${minutes} 分钟。备注：${note}`)
    return ok(ban, 201)
  }

  // 删除只认查询参数；不支持路径参数写法
  if (method === "DELETE" && path === "/bans") {
    const visitor = String(query?.visitor ?? "")
    if (!visitor) return invalid({ visitor: ["请指定要解封的访客。"] })
    if (!removeBan(visitor)) return notFound()
    audit("unban", visitor, "提前解除")
    return ok(null, 204)
  }

  if (method === "GET" && path === "/allowlist") return ok(db().allowlist)

  if (method === "POST" && path === "/allowlist") {
    const entry = String(b.entry ?? "").trim()
    const note = String(b.note ?? "").trim()
    if (!looksLikeEntry(entry)) return invalid({ entry: ["请输入 IP 或网段，例如 203.0.113.10 或 198.51.100.0/28"] })
    if (db().allowlist.data.some((e) => e.entry === entry)) return invalid({ entry: ["这个条目已经在白名单里"] })
    const row: AllowEntry = { entry, note: note || null, added_by: "admin", added_at: new Date().toISOString() }
    db().allowlist.data.push(row)
    removeBan(entry)
    audit("allow_add", entry, `加入白名单，备注：${note || "无"}`)
    return ok(row, 201)
  }

  if (method === "DELETE" && path === "/allowlist") {
    const entry = String(query?.entry ?? "")
    if (!entry) return invalid({ entry: ["请指定要删除的条目。"] })
    const before = db().allowlist.data.length
    db().allowlist.data = db().allowlist.data.filter((e) => e.entry !== entry)
    if (before === db().allowlist.data.length) return notFound()
    audit("allow_remove", entry, "移出白名单")
    return ok(null, 204)
  }

  if (method === "GET" && path === "/settings") return ok(db().settings)

  if (method === "PUT" && path === "/settings") {
    const s = db().settings
    const L = s.limits
    const errors: Record<string, string[]> = {}
    if (b.mode !== undefined && !Object.hasOwn(MODES, b.mode as string)) errors.mode = ["运行模式不在可选范围"]
    const rules = (b.rules ?? []) as Record<string, unknown>[]
    rules.forEach((r, i) => {
      if (!s.rules.some((x) => x.id === r.id)) errors[`rules.${i}.id`] = ["未知的规则。"]
      if (r.action !== undefined && !Object.hasOwn(RULE_ACTIONS, r.action as string)) errors[`rules.${i}.action`] = ["动作不在可选范围"]
      if (r.window_minutes !== undefined) checkRange(errors, `rules.${i}.window_minutes`, r.window_minutes, L.window_minutes)
      if (r.count !== undefined) checkRange(errors, `rules.${i}.count`, r.count, L.count)
      if (r.ban_minutes !== undefined) checkRange(errors, `rules.${i}.ban_minutes`, r.ban_minutes, L.ban_minutes)
    })
    const rep = b.repeat as Record<string, unknown> | undefined
    if (rep) {
      checkRange(errors, "repeat.factor", rep.factor, L.factor)
      checkRange(errors, "repeat.max_days", rep.max_days, L.max_days)
      checkRange(errors, "repeat.keep_days", rep.keep_days, L.keep_days)
    }
    const res = b.response as Record<string, unknown> | undefined
    if (res) {
      if (!L.statuses.includes(res.status as number)) errors["response.status"] = ["状态码不在可选范围"]
      const message = String(res.message ?? "")
      if (!message.trim()) errors["response.message"] = ["请填写提示文字"]
      else if (L.message && message.length > L.message[1]) errors["response.message"] = [`最多 ${L.message[1]} 个字`]
    }
    if (Object.keys(errors).length) return invalid(errors)
    if (b.mode !== undefined && b.mode !== s.mode) audit("mode", "运行模式", `由「${s.mode}」改为「${b.mode as string}」`)
    s.mode = (b.mode as Settings["mode"]) ?? s.mode
    s.rules = s.rules.map((r) => ({ ...r, ...(rules.find((x) => x.id === r.id) ?? {}) }))
    if (rep) s.repeat = { ...s.repeat, ...rep }
    if (res) s.response = { ...s.response, ...res }
    s.updated_by = "admin"
    s.updated_at = new Date().toISOString()
    if (rules.length || rep || res) audit("settings", "防护配置", "修改了防护配置")
    return ok(s)
  }

  if (method === "GET" && path === "/audit") {
    return ok(page(db().audit.filter((a) => !query?.action || a.action === query.action), query))
  }

  return notFound()
}

export async function mockRequest(method: Method, path: string, query?: Query, body?: unknown): Promise<RawResponse> {
  if (import.meta.env.MODE !== "test") await new Promise((r) => setTimeout(r, 250))
  // 深拷贝，避免页面拿到的对象与假数据状态共用引用
  return structuredClone(route(method, path, query, body))
}
