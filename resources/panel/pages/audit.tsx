import { InfoIcon } from "lucide-react"
import * as React from "react"
import { ALL, EmptyRow, LoadError, LoadingRows, Pager } from "@/components/shared"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent } from "@/components/ui/card"
import { Select, SelectContent, SelectGroup, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { api, type AuditAction } from "@/lib/api"
import { AUDIT_ACTIONS, AUDIT_VIA, formatTime } from "@/lib/format"
import { useApi } from "@/lib/use-api"

const PER_PAGE = 20

export function AuditPage() {
  const [action, setAction] = React.useState(ALL)
  const [page, setPage] = React.useState(1)
  const { data, error, loading, reload } = useApi(
    () => api.audit({ action: action === ALL ? undefined : action, page, per_page: PER_PAGE }),
    [action, page],
  )

  return (
    <>
      <Alert>
        <InfoIcon />
        <AlertDescription>管理员在面板和命令行里做的每一次改动都记在这里，最新的在最上面。攻击者触发的封禁在「攻击事件」里。</AlertDescription>
      </Alert>
      <div className="flex flex-wrap items-center gap-2">
        <Select
          value={action}
          onValueChange={(v) => {
            setAction(v)
            setPage(1)
          }}
        >
          <SelectTrigger aria-label="操作类型">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectGroup>
              <SelectItem value={ALL}>全部操作</SelectItem>
              {(Object.keys(AUDIT_ACTIONS) as AuditAction[]).map((a) => (
                <SelectItem key={a} value={a}>
                  {AUDIT_ACTIONS[a]}
                </SelectItem>
              ))}
            </SelectGroup>
          </SelectContent>
        </Select>
      </div>

      {error ? <LoadError error={error} onRetry={reload} /> : null}

      <Card>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>时间</TableHead>
                <TableHead>操作</TableHead>
                <TableHead>对象</TableHead>
                <TableHead>详情</TableHead>
                <TableHead>操作人</TableHead>
                <TableHead>入口</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {loading && !data ? (
                <LoadingRows cols={6} />
              ) : !data || data.data.length === 0 ? (
                <EmptyRow cols={6} text="还没有操作记录" />
              ) : (
                data.data.map((a, i) => (
                  <TableRow key={`${a.time}-${i}`}>
                    <TableCell>{formatTime(a.time)}</TableCell>
                    <TableCell>
                      <Badge variant="outline">{AUDIT_ACTIONS[a.action] ?? a.action}</Badge>
                    </TableCell>
                    <TableCell className="font-mono">{a.target}</TableCell>
                    <TableCell className="max-w-96 min-w-56 whitespace-normal">{a.detail}</TableCell>
                    <TableCell>{a.operator}</TableCell>
                    <TableCell>{AUDIT_VIA[a.via] ?? a.via}</TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </CardContent>
        {data && <Pager page={data.page} perPage={data.per_page} total={data.total} historyLimit={data.history_limit} onPage={setPage} />}
      </Card>
    </>
  )
}
