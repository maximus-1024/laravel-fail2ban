import { mockRequest } from "./mock"

/* ---------- 接口约定里的数据形状 ---------- */

/** 规则标识。规则清单是动态的（宿主可登记自定义规则），界面一律以接口返回为准。 */
type RuleId = string
/** 出现次数怎么数：distinct 按不同地址，each 每次请求都算。 */
export type CountMode = "distinct" | "each"
export type Disposition = "banned" | "expired" | "unbanned" | "exempted" | "recorded"
export type Mode = "off" | "observe" | "block"
export type RuleAction = "ban" | "observe" | "off"
export type AuditAction = "unban" | "ban" | "allow_add" | "allow_remove" | "settings" | "mode"
export type AuditVia = "panel" | "console"

export interface RuleRef {
  id: RuleId
  name: string
}

export interface Incident {
  id: string
  time: string
  visitor: string
  region: string | null
  rule: RuleRef | null
  source: "auto" | "manual"
  count: number | null
  disposition: Disposition
  observe: boolean
  operator: string | null
  note: string | null
}

export interface IncidentDetail extends Incident {
  /** 给人看的一句触发条件，例如「10 分钟内 3 个不同地址」；手动封禁时是「由 admin 操作：备注」。 */
  reason: string | null
  user_agent: string | null
  first_hit_at: string | null
  banned_at: string | null
  unban_at: string | null
  remaining_seconds: number | null
  ban_minutes: number | null
  offense: number | null
  blocked: number | null
  last_blocked_at: string | null
  other_rules: { id: RuleId; name: string; count: number }[]
  requests: { time: string; method: string | null; path: string | null }[]
}

export interface Ban {
  visitor: string
  visitor_note: string | null
  region: string | null
  rule: RuleRef | null
  source: "auto" | "manual"
  reason: string
  banned_at: string
  unban_at: string
  remaining_seconds: number
  total_seconds: number
  blocked: number
  /** 第几次被封；手动封禁时为 null。 */
  offense: number | null
  incident_id: string
  operator: string | null
  note: string | null
}

export interface Ranked {
  key: string
  count: number
}

export interface Overview {
  enabled: boolean
  mode: Mode
  kpis: { blocked: number; new_bans: number; active_bans: number; repeat_offenders: number; hits: number }
  trend: { hour: string; hits: number; blocked: number; bans: number }[]
  rules: { id: RuleId; name: string; hits: number }[]
  top_ips: Ranked[]
  top_targets: Ranked[]
  top_regions: Ranked[]
  recent: Incident[]
}

interface Paged<T> {
  data: T[]
  total: number
  page: number
  per_page: number
}

/** 攻击事件与操作日志的列表：多一个保留条数上限。 */
interface History<T> extends Paged<T> {
  history_limit: number
}

export interface AllowEntry {
  entry: string
  note: string | null
  added_by: string
  added_at: string
}

interface Allowlist {
  builtin: { entry: string; label: string }[]
  data: AllowEntry[]
}

export interface RuleSetting {
  id: RuleId
  name: string
  description: string
  action: RuleAction
  window_minutes: number
  count: number
  ban_minutes: number
  hits_24h: number
  count_mode: CountMode
}

export type Range = [number, number]

export interface Settings {
  enabled: boolean
  mode: Mode
  rules: RuleSetting[]
  repeat: { enabled: boolean; factor: number; max_days: number; keep_days: number }
  response: { status: number; message: string; show_ip: boolean; show_incident: boolean; show_time: boolean }
  limits: {
    window_minutes: Range
    count: Range
    ban_minutes: Range
    factor: Range
    max_days: Range
    keep_days: Range
    statuses: number[]
    /** 提示文字的长度范围；旧版后端没有这一项，此时不限制。 */
    message?: Range
  }
  updated_by: string | null
  updated_at: string | null
}

export interface AuditEntry {
  time: string
  operator: string
  action: AuditAction
  target: string
  detail: string
  via: AuditVia
}

/* ---------- 请求 ---------- */

export type Method = "GET" | "POST" | "PUT" | "DELETE"
export type Query = Record<string, string | number | undefined>

export interface RawResponse {
  status: number
  data: unknown
}

class ApiError extends Error {
  status: number
  errors: Record<string, string[]>

  constructor(status: number, message: string, errors: Record<string, string[]> = {}) {
    super(message)
    this.status = status
    this.errors = errors
  }
}

declare global {
  interface Window {
    Fail2Ban?: { path: string; api: string; user: string }
  }
}

function apiBase(): string {
  return (window.Fail2Ban?.api ?? "/fail2ban/api").replace(/\/+$/, "")
}

function csrfToken(): string {
  return document.querySelector<HTMLMetaElement>('meta[name="csrf-token"]')?.content ?? ""
}

function buildQuery(query?: Query): string {
  if (!query) return ""
  const params = new URLSearchParams()
  for (const [key, value] of Object.entries(query)) {
    if (value !== undefined && value !== "") params.set(key, String(value))
  }
  const text = params.toString()
  return text ? `?${text}` : ""
}

async function fetchTransport(method: Method, path: string, query?: Query, body?: unknown): Promise<RawResponse> {
  const headers: Record<string, string> = { Accept: "application/json", "X-Requested-With": "XMLHttpRequest" }
  if (method !== "GET") {
    headers["X-CSRF-TOKEN"] = csrfToken()
    headers["Content-Type"] = "application/json"
  }
  const res = await fetch(requestUrl(path, query), {
    method,
    headers,
    credentials: "same-origin",
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  const text = await res.text()
  let data: unknown = null
  if (text) {
    try {
      data = JSON.parse(text)
    } catch {
      data = null
    }
  }
  return { status: res.status, data }
}

const STATUS_TEXT: Record<number, string> = {
  401: "登录已失效，请刷新页面重新登录",
  403: "没有权限执行这个操作",
  404: "要找的记录不存在，可能已经到期或被删除",
  419: "页面已过期，请刷新后重试",
  422: "提交的内容有误",
}

/** 完整请求地址；查询参数逐个 URL 编码（访客键与网段里有冒号和斜杠）。 */
export function requestUrl(path: string, query?: Query): string {
  return apiBase() + path + buildQuery(query)
}

async function request<T>(method: Method, path: string, options: { query?: Query; body?: unknown } = {}): Promise<T> {
  // 开发环境（npm run dev / vitest）走假数据；生产构建里 import.meta.env.DEV 为 false，
  // 这个分支连同 ./mock 整个模块都会被摇掉。
  const res = import.meta.env.DEV
    ? await mockRequest(method, path, options.query, options.body)
    : await fetchTransport(method, path, options.query, options.body)

  if (res.status >= 200 && res.status < 300) return res.data as T

  const payload = (res.data ?? {}) as { message?: unknown; errors?: unknown }
  const errors = (payload.errors && typeof payload.errors === "object" ? payload.errors : {}) as Record<string, string[]>
  const message =
    res.status === 422 || typeof payload.message !== "string" || !payload.message
      ? (STATUS_TEXT[res.status] ?? `请求失败（${res.status}）`)
      : payload.message
  throw new ApiError(res.status, message, errors)
}

export const api = {
  overview: (hours: number) => request<Overview>("GET", "/overview", { query: { hours } }),
  incidents: (query: Query) => request<History<Incident>>("GET", "/incidents", { query }),
  incident: (id: string) => request<IncidentDetail>("GET", `/incidents/${encodeURIComponent(id)}`),
  bans: (query: Query) => request<{ data: Ban[]; total: number }>("GET", "/bans", { query }),
  ban: (body: { ip: string; minutes: number; note: string }) => request<Ban>("POST", "/bans", { body }),
  // 访客键与网段可能含冒号和斜杠，放在查询参数里，不放进路径。
  unban: (visitor: string) => request<null>("DELETE", "/bans", { query: { visitor } }),
  allowlist: () => request<Allowlist>("GET", "/allowlist"),
  allow: (body: { entry: string; note: string }) => request<AllowEntry>("POST", "/allowlist", { body }),
  disallow: (entry: string) => request<null>("DELETE", "/allowlist", { query: { entry } }),
  settings: () => request<Settings>("GET", "/settings"),
  saveSettings: (body: Partial<Pick<Settings, "mode" | "repeat" | "response">> & { rules?: Partial<RuleSetting>[] }) =>
    request<Settings>("PUT", "/settings", { body }),
  audit: (query: Query) => request<History<AuditEntry>>("GET", "/audit", { query }),
}

/** 422 的第一条字段错误；字段名按接口返回的键（如 `ip`、`rules.0.count`、`repeat.factor`）。 */
export function fieldError(error: unknown, field: string): string | undefined {
  if (error instanceof ApiError) return error.errors[field]?.[0]
  return undefined
}

export function errorMessage(error: unknown): string {
  if (error instanceof ApiError) {
    const first = Object.values(error.errors)[0]?.[0]
    return first ?? error.message
  }
  return "网络错误，请稍后重试"
}
