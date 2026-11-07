import { InboxIcon } from "lucide-react"
import { useStatus } from "@/components/status"
import { Alert, AlertAction, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Empty, EmptyHeader, EmptyMedia, EmptyTitle } from "@/components/ui/empty"
import { Item, ItemContent, ItemDescription, ItemTitle } from "@/components/ui/item"
import { errorMessage, type Incident } from "@/lib/api"
import { DISPOSITIONS } from "@/lib/format"

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

/** 「触发规则」筛选的选项：接口返回的规则，加上手动封禁。 */
export function useRuleOptions() {
  const rules = useStatus().settings?.rules ?? []
  return [...rules.map((r) => ({ value: r.id, label: r.name })), { value: "manual", label: "手动封禁" }]
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

/** 空态：表格、排行卡片与详情抽屉共用同一个 Empty。 */
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
