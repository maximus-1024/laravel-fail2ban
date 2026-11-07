import * as React from "react"
import { IncidentSheet } from "@/components/incident-sheet"
import { ALL, EmptyRow, IncidentRow, LoadError, LoadingRows, Pager, RuleSelect } from "@/components/shared"
import { Button } from "@/components/ui/button"
import { Card, CardContent } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Table, TableBody, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { api, type Disposition } from "@/lib/api"
import { DISPOSITIONS } from "@/lib/format"
import { useApi } from "@/lib/use-api"

const PER_PAGE = 20

export function IncidentsPage() {
  const [disposition, setDisposition] = React.useState(ALL)
  const [rule, setRule] = React.useState(ALL)
  const [search, setSearch] = React.useState("")
  const [q, setQ] = React.useState("")
  const [page, setPage] = React.useState(1)
  const [incident, setIncident] = React.useState<string | null>(null)

  const { data, error, loading, reload } = useApi(
    () =>
      api.incidents({
        disposition: disposition === ALL ? undefined : disposition,
        rule: rule === ALL ? undefined : rule,
        q: q || undefined,
        page,
        per_page: PER_PAGE,
      }),
    [disposition, rule, q, page],
  )

  return (
    <>
      <form
        className="flex flex-wrap items-center gap-2"
        onSubmit={(e) => {
          e.preventDefault()
          setPage(1)
          setQ(search.trim())
        }}
      >
        <Select
          value={disposition}
          onValueChange={(v) => {
            setDisposition(v)
            setPage(1)
          }}
        >
          <SelectTrigger aria-label="处置">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value={ALL}>全部处置</SelectItem>
            {(Object.keys(DISPOSITIONS) as Disposition[]).map((d) => (
              <SelectItem key={d} value={d}>
                {DISPOSITIONS[d].label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <RuleSelect
          value={rule}
          onChange={(v) => {
            setRule(v)
            setPage(1)
          }}
        />
        <Input className="w-full sm:w-64" placeholder="搜索 IP 或事件编号" aria-label="搜索 IP 或事件编号" value={search} onChange={(e) => setSearch(e.target.value)} />
        <Button type="submit" variant="outline">
          搜索
        </Button>
      </form>

      {error ? <LoadError error={error} onRetry={reload} /> : null}

      <Card>
        <CardContent className="grid gap-4">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>时间</TableHead>
                <TableHead>攻击 IP</TableHead>
                <TableHead>地区</TableHead>
                <TableHead>事件编号</TableHead>
                <TableHead>触发规则</TableHead>
                <TableHead>命中次数</TableHead>
                <TableHead>处置</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {loading && !data ? (
                <LoadingRows cols={7} />
              ) : !data || data.data.length === 0 ? (
                <EmptyRow cols={7} text={q || disposition !== ALL || rule !== ALL ? "没有符合条件的事件" : "还没有攻击事件"} />
              ) : (
                data.data.map((i) => <IncidentRow key={i.id} incident={i} showId onOpen={setIncident} />)
              )}
            </TableBody>
          </Table>
          {data && <Pager page={data.page} perPage={data.per_page} total={data.total} historyLimit={data.history_limit} onPage={setPage} />}
        </CardContent>
      </Card>

      <IncidentSheet id={incident} onClose={() => setIncident(null)} onChanged={reload} />
    </>
  )
}
