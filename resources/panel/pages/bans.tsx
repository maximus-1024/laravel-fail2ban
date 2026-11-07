import * as React from "react"
import { BanDialog } from "@/components/ban-dialog"
import { ConfirmUnban } from "@/components/confirm-button"
import { IncidentSheet } from "@/components/incident-sheet"
import { ALL, EmptyRow, LoadError, LoadingRows, RuleSelect } from "@/components/shared"
import { useStatus } from "@/components/status"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Progress } from "@/components/ui/progress"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { api } from "@/lib/api"
import { formatNumber, formatRemaining, formatTime, regionName } from "@/lib/format"
import { useApi } from "@/lib/use-api"

export function BansPage() {
  const [rule, setRule] = React.useState(ALL)
  const [search, setSearch] = React.useState("")
  const [q, setQ] = React.useState("")
  const [incident, setIncident] = React.useState<string | null>(null)
  const mode = useStatus().settings?.mode
  const { data, error, loading, reload } = useApi(() => api.bans({ rule: rule === ALL ? undefined : rule, q: q || undefined }), [rule, q])

  return (
    <>
      <div className="flex flex-wrap items-center gap-2">
        <form
          className="flex flex-1 flex-wrap items-center gap-2"
          onSubmit={(e) => {
            e.preventDefault()
            setQ(search.trim())
          }}
        >
          <Input className="w-full sm:w-56" placeholder="搜索 IP" aria-label="搜索 IP" value={search} onChange={(e) => setSearch(e.target.value)} />
          <RuleSelect value={rule} onChange={setRule} />
          <Button type="submit" variant="outline">
            搜索
          </Button>
        </form>
        <BanDialog onDone={reload} />
      </div>

      {error ? <LoadError error={error} onRetry={reload} /> : null}
      {mode === "observe" && <p className="text-sm text-muted-foreground">当前是观察模式：封禁照常记录，但不会真正拦截请求。</p>}

      <Card>
        <CardContent className="grid gap-4">
          <p className="text-sm text-muted-foreground">{data ? `共 ${data.total} 个访客正在被封禁` : "加载中…"}</p>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>攻击 IP</TableHead>
                <TableHead>地区</TableHead>
                <TableHead>触发规则</TableHead>
                <TableHead>封禁时间</TableHead>
                <TableHead>解封时间</TableHead>
                <TableHead>剩余时间</TableHead>
                <TableHead>已拦截</TableHead>
                <TableHead>操作</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {loading && !data ? (
                <LoadingRows cols={8} />
              ) : !data || data.data.length === 0 ? (
                <EmptyRow cols={8} text={q || rule !== ALL ? "没有符合条件的封禁" : "当前没有被封禁的访客"} />
              ) : (
                data.data.map((b) => (
                  <TableRow key={b.visitor}>
                    <TableCell>
                      <div className="font-mono">{b.visitor}</div>
                      {b.visitor_note && <div className="text-xs text-muted-foreground">{b.visitor_note}</div>}
                    </TableCell>
                    <TableCell>{b.region ? regionName(b.region) : "—"}</TableCell>
                    <TableCell className="max-w-72 min-w-48 whitespace-normal">
                      <div>{b.rule ? b.rule.name : "手动封禁"}</div>
                      <div className="text-xs text-muted-foreground">{b.reason}</div>
                      {(b.offense ?? 0) > 1 && (
                        <Badge variant="secondary" className="mt-1">
                          累犯第 {b.offense} 次，时长已加长
                        </Badge>
                      )}
                    </TableCell>
                    <TableCell>{formatTime(b.banned_at)}</TableCell>
                    <TableCell>{formatTime(b.unban_at)}</TableCell>
                    <TableCell className="min-w-32">
                      <div className="text-sm">{formatRemaining(b.remaining_seconds)}</div>
                      <Progress
                        className="mt-1"
                        value={b.total_seconds > 0 ? (b.remaining_seconds / b.total_seconds) * 100 : 0}
                        aria-label={`剩余时间 ${formatRemaining(b.remaining_seconds)}`}
                      />
                    </TableCell>
                    <TableCell>{formatNumber(b.blocked)} 次</TableCell>
                    <TableCell>
                      <div className="flex gap-2">
                        <Button variant="ghost" size="sm" onClick={() => setIncident(b.incident_id)}>
                          详情
                        </Button>
                        <ConfirmUnban visitor={b.visitor} onDone={reload} />
                      </div>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
          <p className="text-sm text-muted-foreground">到了解封时间自动解除。手动解封会同时清空该访客的命中记录。</p>
        </CardContent>
      </Card>

      <IncidentSheet id={incident} onClose={() => setIncident(null)} onChanged={reload} />
    </>
  )
}
