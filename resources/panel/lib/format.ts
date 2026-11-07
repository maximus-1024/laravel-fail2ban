import type { AuditAction, AuditVia, CountMode, Disposition, Mode, RuleAction, Settings } from "./api"

/** 出现次数的量词，按接口返回的 count_mode。 */
export function countUnit(mode: CountMode): string {
  return mode === "distinct" ? "个不同地址" : "次"
}

/** 两个字母的国家代码（NL、US）转成简体中文国名；转不了就原样显示代码。 */
let regions: Intl.DisplayNames | undefined
export function regionName(code: string): string {
  try {
    regions ??= new Intl.DisplayNames(["zh-Hans"], { type: "region" })
    return regions.of(code) ?? code
  } catch {
    return code
  }
}

/**
 * 第 offense 次被封的时长（分钟），与后端 BanDuration 一致：规则的封禁时长乘以倍数的 offense-1 次方，
 * 不超过封顶；规则的封禁时长本身比封顶长时按规则的时长。
 */
export function offenseMinutes(base: number, offense: number, repeat: Pick<Settings["repeat"], "enabled" | "factor" | "max_days">): number {
  if (!repeat.enabled || repeat.factor < 2) return base
  return Math.max(base, Math.min(base * repeat.factor ** (offense - 1), repeat.max_days * 1440))
}

export const DISPOSITIONS: Record<Disposition, { label: string; variant: "destructive" | "secondary" | "outline" }> = {
  banned: { label: "已封禁", variant: "destructive" },
  expired: { label: "已到期", variant: "secondary" },
  unbanned: { label: "已解封", variant: "outline" },
  exempted: { label: "已豁免", variant: "outline" },
  recorded: { label: "仅记录", variant: "secondary" },
}

export const MODES: Record<Mode, string> = {
  off: "已关闭",
  observe: "观察模式",
  block: "拦截模式",
}

export const RULE_ACTIONS: Record<RuleAction, { label: string; hint: string }> = {
  ban: { label: "封禁", hint: "达到出现次数就封禁这个访客。它不拦达到次数的那一次请求，从下一次请求开始拦。" },
  observe: { label: "观察", hint: "达到出现次数只记一条事件，不封禁。新规则建议先观察几天。" },
  off: { label: "关闭", hint: "这条规则不统计，也不记录。" },
}

export const AUDIT_VIA: Record<AuditVia, string> = {
  panel: "面板",
  console: "命令行",
}

export const AUDIT_ACTIONS: Record<AuditAction, string> = {
  ban: "手动封禁",
  unban: "解封",
  allow_add: "加入白名单",
  allow_remove: "移出白名单",
  settings: "配置变更",
  mode: "运行模式",
}

const pad = (n: number) => String(n).padStart(2, "0")

function dayDiff(date: Date, now: Date): number {
  const a = new Date(date.getFullYear(), date.getMonth(), date.getDate()).getTime()
  const b = new Date(now.getFullYear(), now.getMonth(), now.getDate()).getTime()
  return Math.round((a - b) / 86_400_000)
}

/** 「今天 14:02:11」「昨天 …」「明天 …」，更远的显示日期。 */
export function formatTime(iso: string | null | undefined, now = new Date()): string {
  if (!iso) return "—"
  const date = new Date(iso)
  if (Number.isNaN(date.getTime())) return iso
  const clock = `${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`
  const diff = dayDiff(date, now)
  if (diff === 0) return `今天 ${clock}`
  if (diff === -1) return `昨天 ${clock}`
  if (diff === 1) return `明天 ${clock}`
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}`
}

export function formatClock(iso: string | null | undefined): string {
  if (!iso) return "—"
  const date = new Date(iso)
  if (Number.isNaN(date.getTime())) return iso
  return `${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`
}

export function formatHour(iso: string): string {
  const date = new Date(iso)
  if (Number.isNaN(date.getTime())) return iso
  return `${pad(date.getHours())}:00`
}

/** 剩余秒数：「1 小时 54 分」「13 分 01 秒」「45 秒」。 */
export function formatRemaining(seconds: number | null | undefined): string {
  if (seconds == null || seconds <= 0) return "已到期"
  const s = Math.floor(seconds)
  if (s >= 3600) return `${Math.floor(s / 3600)} 小时 ${Math.floor((s % 3600) / 60)} 分`
  if (s >= 60) return `${Math.floor(s / 60)} 分 ${pad(s % 60)} 秒`
  return `${s} 秒`
}

/** 分钟数的白话：「30 分钟」「2 小时」「1.5 小时」「7 天」。 */
export function humanMinutes(minutes: number): string {
  if (!(minutes > 0)) return "请填写分钟数"
  if (minutes >= 1440 && minutes % 1440 === 0) return `${minutes / 1440} 天`
  if (minutes >= 60) return `${Math.round(minutes / 6) / 10} 小时`
  return `${minutes} 分钟`
}

export function formatNumber(n: number): string {
  return n.toLocaleString("en-US")
}
