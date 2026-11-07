import { createColumnHelper, useTable } from "@tanstack/react-table"
import { CopyIcon } from "lucide-react"
import { DataTable, DataTablePagination, DataTableToolbar, RowActions, features, filterValue, useTableState, type Features } from "@/components/data-table"
import { PageHeader } from "@/components/page-header"
import { LoadError } from "@/components/shared"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardDescription, CardFooter } from "@/components/ui/card"
import { DropdownMenuGroup, DropdownMenuItem } from "@/components/ui/dropdown-menu"
import { api, type AuditAction, type AuditEntry } from "@/lib/api"
import { copyText } from "@/lib/clipboard"
import { AUDIT_ACTIONS, AUDIT_VIA, formatNumber, formatTime } from "@/lib/format"
import { useApi } from "@/lib/use-api"

const ACTION_OPTIONS = (Object.keys(AUDIT_ACTIONS) as AuditAction[]).map((a) => ({ value: a, label: AUDIT_ACTIONS[a] }))
const column = createColumnHelper<Features, AuditEntry>()
const NONE: AuditEntry[] = []

const columns = column.columns([
  column.accessor("time", {
    header: "时间",
    meta: { label: "时间" },
    cell: ({ getValue }) => <span className="font-mono">{formatTime(getValue())}</span>,
  }),
  column.accessor("action", {
    header: "操作",
    filterFn: "arrIncludesSome",
    meta: { label: "操作" },
    cell: ({ getValue }) => <Badge variant="outline">{AUDIT_ACTIONS[getValue()] ?? getValue()}</Badge>,
  }),
  column.accessor("target", {
    header: "对象",
    enableHiding: false,
    cell: ({ getValue }) => <span className="font-mono">{getValue()}</span>,
  }),
  column.accessor("detail", {
    header: "详情",
    meta: { label: "详情", className: "max-w-96 min-w-56 whitespace-normal" },
  }),
  column.accessor("operator", { header: "操作人", meta: { label: "操作人" } }),
  column.accessor("via", {
    header: "入口",
    meta: { label: "入口" },
    cell: ({ getValue }) => AUDIT_VIA[getValue()] ?? getValue(),
  }),
  column.display({
    id: "actions",
    enableHiding: false,
    cell: ({ row: { original: a } }) => (
      <RowActions label={`${a.target} 的更多操作`}>
        <DropdownMenuGroup>
          <DropdownMenuItem onSelect={() => copyText(a.target, "对象")}>
            <CopyIcon />
            复制对象
          </DropdownMenuItem>
        </DropdownMenuGroup>
      </RowActions>
    ),
  }),
])

export function AuditPage() {
  const state = useTableState()
  const { columnFilters, pagination } = state
  const action = filterValue(columnFilters, "action")
  const { data, error, loading, reload } = useApi(
    () => api.audit({ action, page: pagination.pageIndex + 1, per_page: pagination.pageSize }),
    [action, pagination.pageIndex, pagination.pageSize],
  )
  const table = useTable({
    features,
    data: data?.data ?? NONE,
    columns,
    getRowId: (a, i) => `${a.time}-${i}`,
    ...state.options,
    manualPagination: true,
    rowCount: data?.total ?? 0,
  })

  return (
    <>
      <PageHeader title="操作日志" description="管理员在面板和命令行里做的每一次改动都记在这里，最新的在最上面。攻击者触发的封禁在「攻击事件」里。" />
      <DataTableToolbar table={table} filters={[{ columnId: "action", title: "操作类型", options: ACTION_OPTIONS }]} />

      {error ? <LoadError error={error} onRetry={reload} /> : null}

      <Card>
        <CardContent>
          <DataTable table={table} loading={loading && !data} empty={action ? "没有符合条件的操作记录" : "还没有操作记录"} />
        </CardContent>
        <CardFooter>
          <DataTablePagination
            table={table}
            summary={<CardDescription>{data ? `共 ${formatNumber(data.total)} 条，只保留最近 ${data.history_limit} 条` : "加载中…"}</CardDescription>}
          />
        </CardFooter>
      </Card>
    </>
  )
}
