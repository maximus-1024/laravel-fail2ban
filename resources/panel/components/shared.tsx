import { InboxIcon } from "lucide-react"
import { useStatus } from "@/components/status"
import { Alert, AlertAction, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { CardDescription, CardFooter } from "@/components/ui/card"
import { Empty, EmptyHeader, EmptyMedia, EmptyTitle } from "@/components/ui/empty"
import { Item, ItemContent, ItemDescription, ItemTitle } from "@/components/ui/item"
import { Select, SelectContent, SelectGroup, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
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

/** 表格里的两行文字：主文字加一行说明，排版全部交给 Item。 */
export function CellText({ title, description, mono, children }: { title: React.ReactNode; description?: React.ReactNode; mono?: boolean; children?: React.ReactNode }) {
  return (
    <Item size="xs" className="p-0">
      <ItemContent>
        <ItemTitle className={mono ? "font-mono" : undefined}>{title}</ItemTitle>
        {description && <ItemDescription>{description}</ItemDescription>}
        {children}
      </ItemContent>
    </Item>
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
        <Button variant="link" className="px-0 font-mono" onClick={() => onOpen(i.id)}>
          {i.visitor}
        </Button>
      </TableCell>
      <TableCell>{i.region ? regionName(i.region) : "—"}</TableCell>
      {showId && <TableCell className="font-mono">{i.id}</TableCell>}
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
        <SelectGroup>
          <SelectItem value={ALL}>全部规则</SelectItem>
          {rules.map((r) => (
            <SelectItem key={r.id} value={r.id}>
              {r.name}
            </SelectItem>
          ))}
          <SelectItem value="manual">手动封禁</SelectItem>
        </SelectGroup>
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

/** 空态：Empty 组件；表格里用 EmptyRow 占满一行。 */
export function EmptyState({ text = "暂无数据" }: { text?: string }) {
  return (
    <Empty>
      <EmptyHeader>
        <EmptyMedia variant="icon">
          <InboxIcon />
        </EmptyMedia>
        <EmptyTitle>{text}</EmptyTitle>
      </EmptyHeader>
    </Empty>
  )
}

export function EmptyRow({ cols, text }: { cols: number; text?: string }) {
  return (
    <TableRow>
      <TableCell colSpan={cols}>
        <EmptyState text={text} />
      </TableCell>
    </TableRow>
  )
}

/** 分页：照数据表格示例，上一页、下一页两个按钮，放在卡片底部。 */
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
    <CardFooter className="flex-wrap justify-between gap-2">
      <CardDescription>
        共 {total} 条{historyLimit ? `，只保留最近 ${historyLimit} 条` : ""}
      </CardDescription>
      <div className="flex items-center gap-2">
        <Button variant="outline" size="sm" disabled={page <= 1} onClick={() => onPage(page - 1)}>
          上一页
        </Button>
        <CardDescription>
          第 {page} / {pages} 页
        </CardDescription>
        <Button variant="outline" size="sm" disabled={page >= pages} onClick={() => onPage(page + 1)}>
          下一页
        </Button>
      </div>
    </CardFooter>
  )
}
