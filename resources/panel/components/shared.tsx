import { useStatus } from "@/components/status"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Alert, AlertAction, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Skeleton } from "@/components/ui/skeleton"
import { TableCell, TableRow } from "@/components/ui/table"
import { errorMessage, type Incident } from "@/lib/api"
import { DISPOSITIONS, formatTime, regionName } from "@/lib/format"

/** 筛选下拉里「全部」的取值。 */
export const ALL = "all"

export function DispositionBadge({ incident }: { incident: Pick<Incident, "disposition" | "observe"> }) {
  const d = DISPOSITIONS[incident.disposition]
  return (
    <span className="inline-flex flex-wrap gap-1">
      <Badge variant={d.variant}>{d.label}</Badge>
      {incident.observe && <Badge variant="outline">观察</Badge>}
    </span>
  )
}

/** 触发规则：自动封禁显示规则名，手动封禁显示操作人。 */
export function RuleText({ incident }: { incident: Pick<Incident, "rule" | "operator" | "source"> }) {
  if (incident.rule) return <>{incident.rule.name}</>
  return <>手动封禁{incident.operator ? `，由 ${incident.operator} 操作` : ""}</>
}

/** 一行攻击事件：安全总览的最近事件与攻击事件页共用；showId 时多一列事件编号。 */
export function IncidentRow({ incident: i, showId, onOpen }: { incident: Incident; showId?: boolean; onOpen: (id: string) => void }) {
  return (
    <TableRow className="cursor-pointer" onClick={() => onOpen(i.id)}>
      <TableCell>{formatTime(i.time)}</TableCell>
      <TableCell>
        <Button variant="link" className="h-auto p-0 font-mono" onClick={() => onOpen(i.id)}>
          {i.visitor}
        </Button>
      </TableCell>
      <TableCell>{i.region ? regionName(i.region) : "—"}</TableCell>
      {showId && <TableCell className="font-mono text-xs text-muted-foreground">{i.id}</TableCell>}
      <TableCell>
        <RuleText incident={i} />
      </TableCell>
      <TableCell>{i.count == null ? "无" : `${i.count} 次`}</TableCell>
      <TableCell>
        <DispositionBadge incident={i} />
      </TableCell>
    </TableRow>
  )
}

/** 「触发规则」筛选：全部、接口返回的规则、手动封禁。 */
export function RuleSelect({ value, onChange }: { value: string; onChange: (value: string) => void }) {
  const rules = useStatus().settings?.rules ?? []
  return (
    <Select value={value} onValueChange={onChange}>
      <SelectTrigger aria-label="触发规则">
        <SelectValue />
      </SelectTrigger>
      <SelectContent>
        <SelectItem value={ALL}>全部规则</SelectItem>
        {rules.map((r) => (
          <SelectItem key={r.id} value={r.id}>
            {r.name}
          </SelectItem>
        ))}
        <SelectItem value="manual">手动封禁</SelectItem>
      </SelectContent>
    </Select>
  )
}

export function LoadError({ error, onRetry }: { error: unknown; onRetry: () => void }) {
  return (
    <Alert variant="destructive">
      <AlertTitle>加载失败</AlertTitle>
      <AlertDescription>{errorMessage(error)}</AlertDescription>
      <AlertAction>
        <Button size="sm" variant="outline" onClick={onRetry}>
          重试
        </Button>
      </AlertAction>
    </Alert>
  )
}

export function LoadingRows({ cols, rows = 4 }: { cols: number; rows?: number }) {
  return (
    <>
      {Array.from({ length: rows }, (_, r) => (
        <TableRow key={r}>
          {Array.from({ length: cols }, (_, c) => (
            <TableCell key={c}>
              <Skeleton className="h-4 w-full" />
            </TableCell>
          ))}
        </TableRow>
      ))}
    </>
  )
}

export function EmptyRow({ cols, text = "暂无数据" }: { cols: number; text?: string }) {
  return (
    <TableRow>
      <TableCell colSpan={cols} className="h-24 text-center text-muted-foreground">
        {text}
      </TableCell>
    </TableRow>
  )
}

export function FieldError({ message }: { message?: string }) {
  if (!message) return null
  return <p className="text-sm text-destructive">{message}</p>
}

export function Pager({
  page,
  perPage,
  total,
  historyLimit,
  onPage,
}: {
  page: number
  perPage: number
  total: number
  /** 只保留最近多少条（接口的 history_limit）。 */
  historyLimit?: number
  onPage: (p: number) => void
}) {
  const pages = Math.max(1, Math.ceil(total / perPage))
  return (
    <div className="flex flex-wrap items-center justify-between gap-2 text-sm text-muted-foreground">
      <span>
        共 {total} 条{historyLimit ? `，只保留最近 ${historyLimit} 条` : ""}
      </span>
      <div className="flex items-center gap-2">
        <Button variant="outline" size="sm" disabled={page <= 1} onClick={() => onPage(page - 1)}>
          上一页
        </Button>
        <span className="whitespace-nowrap">
          第 {page} / {pages} 页
        </span>
        <Button variant="outline" size="sm" disabled={page >= pages} onClick={() => onPage(page + 1)}>
          下一页
        </Button>
      </div>
    </div>
  )
}
