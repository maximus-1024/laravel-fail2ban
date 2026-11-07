import * as React from "react"
import { DataTable, DataTablePagination, DataTableToolbar, filterValue, useTableState } from "@/components/data-table"
import { IncidentSheet } from "@/components/incident-sheet"
import { useIncidentTable } from "@/components/incident-table"
import { PageHeader } from "@/components/page-header"
import { LoadError, useRuleOptions } from "@/components/shared"
import { Card, CardContent, CardDescription, CardFooter } from "@/components/ui/card"
import { api, type Disposition } from "@/lib/api"
import { DISPOSITIONS, formatNumber } from "@/lib/format"
import { useApi } from "@/lib/use-api"

const DISPOSITION_OPTIONS = (Object.keys(DISPOSITIONS) as Disposition[]).map((d) => ({ value: d, label: DISPOSITIONS[d].label }))

export function IncidentsPage() {
  const [incident, setIncident] = React.useState<string | null>(null)
  const ruleOptions = useRuleOptions()
  const state = useTableState()
  const { q, columnFilters, pagination } = state
  const disposition = filterValue(columnFilters, "disposition")
  const rule = filterValue(columnFilters, "rule")

  const { data, error, loading, reload } = useApi(
    () => api.incidents({ disposition, rule, q: q || undefined, page: pagination.pageIndex + 1, per_page: pagination.pageSize }),
    [disposition, rule, q, pagination.pageIndex, pagination.pageSize],
  )
  const table = useIncidentTable({
    data: data?.data,
    onOpen: setIncident,
    options: { ...state.options, manualPagination: true, rowCount: data?.total ?? 0 },
  })

  return (
    <>
      <PageHeader title="攻击事件" description="每次触发规则或手动封禁都记一条事件，最新的在最上面。点一行查看详情。" />
      <DataTableToolbar
        table={table}
        search={q}
        onSearch={state.setQ}
        placeholder="搜索 IP 或事件编号"
        filters={[
          { columnId: "disposition", title: "处置", options: DISPOSITION_OPTIONS },
          { columnId: "rule", title: "触发规则", options: ruleOptions },
        ]}
      />

      {error ? <LoadError error={error} onRetry={reload} /> : null}

      <Card>
        <CardContent>
          <DataTable table={table} loading={loading && !data} empty={q || disposition || rule ? "没有符合条件的事件" : "还没有攻击事件"} onRowClick={(i) => setIncident(i.id)} />
        </CardContent>
        <CardFooter>
          <DataTablePagination
            table={table}
            summary={<CardDescription>{data ? `共 ${formatNumber(data.total)} 条，只保留最近 ${data.history_limit} 条` : "加载中…"}</CardDescription>}
          />
        </CardFooter>
      </Card>

      <IncidentSheet id={incident} onClose={() => setIncident(null)} onChanged={reload} />
    </>
  )
}
