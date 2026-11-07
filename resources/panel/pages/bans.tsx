import { createColumnHelper, useTable } from "@tanstack/react-table"
import { CopyIcon, InfoIcon, PanelRightOpenIcon } from "lucide-react"
import * as React from "react"
import { BanDialog } from "@/components/ban-dialog"
import { ConfirmUnban } from "@/components/confirm-button"
import { DataTable, DataTablePagination, DataTableToolbar, RowActions, features, filterValue, useTableState, type Features } from "@/components/data-table"
import { IncidentSheet } from "@/components/incident-sheet"
import { PageHeader } from "@/components/page-header"
import { CellText, LoadError, useRuleOptions } from "@/components/shared"
import { useStatus } from "@/components/status"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardDescription, CardFooter } from "@/components/ui/card"
import { DropdownMenuGroup, DropdownMenuItem } from "@/components/ui/dropdown-menu"
import { Progress } from "@/components/ui/progress"
import { api, type Ban } from "@/lib/api"
import { copyText } from "@/lib/clipboard"
import { formatNumber, formatRemaining, formatTime, regionName } from "@/lib/format"
import { useApi } from "@/lib/use-api"

const column = createColumnHelper<Features, Ban>()
const NONE: Ban[] = []

function banColumns(onOpen: (id: string) => void, onChanged: () => void) {
  return column.columns([
    column.accessor("visitor", {
      header: "攻击 IP",
      enableHiding: false,
      cell: ({ row }) => <CellText title={row.original.visitor} description={row.original.visitor_note} mono />,
    }),
    column.accessor("region", {
      header: "地区",
      meta: { label: "地区" },
      cell: ({ getValue }) => {
        const region = getValue()
        return region ? regionName(region) : "—"
      },
    }),
    column.accessor((b) => b.rule?.id ?? "manual", {
      id: "rule",
      header: "触发规则",
      filterFn: "arrIncludesSome",
      meta: { label: "触发规则", className: "max-w-72 min-w-48 whitespace-normal" },
      cell: ({ row: { original: b } }) => (
        <CellText title={b.rule ? b.rule.name : "手动封禁"} description={b.reason}>
          {(b.offense ?? 0) > 1 && <Badge variant="secondary">累犯第 {b.offense} 次，时长已加长</Badge>}
        </CellText>
      ),
    }),
    column.accessor("banned_at", {
      header: "封禁时间",
      meta: { label: "封禁时间" },
      cell: ({ getValue }) => <span className="font-mono">{formatTime(getValue())}</span>,
    }),
    column.accessor("unban_at", {
      header: "解封时间",
      meta: { label: "解封时间" },
      cell: ({ getValue }) => <span className="font-mono">{formatTime(getValue())}</span>,
    }),
    column.accessor("remaining_seconds", {
      header: "剩余时间",
      meta: { label: "剩余时间", className: "min-w-32" },
      cell: ({ row: { original: b } }) => (
        <div className="flex flex-col gap-1">
          <span className="tabular-nums">{formatRemaining(b.remaining_seconds)}</span>
          <Progress value={b.total_seconds > 0 ? (b.remaining_seconds / b.total_seconds) * 100 : 0} aria-label={`剩余时间 ${formatRemaining(b.remaining_seconds)}`} />
        </div>
      ),
    }),
    column.accessor("blocked", {
      header: "已拦截",
      meta: { label: "已拦截", className: "text-right tabular-nums" },
      cell: ({ getValue }) => `${formatNumber(getValue())} 次`,
    }),
    column.display({
      id: "actions",
      header: () => <span className="sr-only">操作</span>,
      enableHiding: false,
      cell: ({ row: { original: b } }) => (
        <div className="flex items-center justify-end gap-1">
          <ConfirmUnban visitor={b.visitor} onDone={onChanged} />
          <RowActions label={`${b.visitor} 的更多操作`}>
            <DropdownMenuGroup>
              <DropdownMenuItem onSelect={() => onOpen(b.incident_id)}>
                <PanelRightOpenIcon />
                查看事件详情
              </DropdownMenuItem>
              <DropdownMenuItem onSelect={() => copyText(b.visitor, " IP")}>
                <CopyIcon />
                复制 IP
              </DropdownMenuItem>
              <DropdownMenuItem onSelect={() => copyText(b.incident_id, "事件编号")}>
                <CopyIcon />
                复制事件编号
              </DropdownMenuItem>
            </DropdownMenuGroup>
          </RowActions>
        </div>
      ),
    }),
  ])
}

export function BansPage() {
  const [incident, setIncident] = React.useState<string | null>(null)
  const mode = useStatus().settings?.mode
  const ruleOptions = useRuleOptions()
  const state = useTableState()
  const { q, columnFilters } = state
  const rule = filterValue(columnFilters, "rule")
  // 封禁列表接口一次返回全部当前封禁，不分页；筛选与搜索交给接口，分页在本地做
  const { data, error, loading, reload } = useApi(() => api.bans({ rule, q: q || undefined }), [rule, q])
  const columns = React.useMemo(() => banColumns(setIncident, reload), [reload])
  const table = useTable({ features, data: data?.data ?? NONE, columns, getRowId: (b) => b.visitor, ...state.options })

  return (
    <>
      <PageHeader title="封禁列表" description="到了解封时间自动解除。手动解封会同时清空该访客的命中记录。" actions={<BanDialog onDone={reload} />} />
      <DataTableToolbar table={table} search={q} onSearch={state.setQ} placeholder="搜索 IP" filters={[{ columnId: "rule", title: "触发规则", options: ruleOptions }]} />

      {error ? <LoadError error={error} onRetry={reload} /> : null}
      {mode === "observe" && (
        <Alert>
          <InfoIcon />
          <AlertDescription>当前是观察模式：封禁照常记录，但不会真正拦截请求。</AlertDescription>
        </Alert>
      )}

      <Card>
        <CardContent>
          <DataTable table={table} loading={loading && !data} empty={q || rule ? "没有符合条件的封禁" : "当前没有被封禁的访客"} />
        </CardContent>
        <CardFooter>
          <DataTablePagination table={table} summary={<CardDescription>{data ? `共 ${data.total} 个访客正在被封禁` : "加载中…"}</CardDescription>} />
        </CardFooter>
      </Card>

      <IncidentSheet id={incident} onClose={() => setIncident(null)} onChanged={reload} />
    </>
  )
}
