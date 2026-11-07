import * as React from "react"
import { Area, AreaChart, CartesianGrid, XAxis, YAxis } from "recharts"
import { IncidentSheet } from "@/components/incident-sheet"
import { EmptyRow, IncidentRow, LoadError, LoadingRows } from "@/components/shared"
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { ChartContainer, ChartLegend, ChartLegendContent, ChartTooltip, ChartTooltipContent, type ChartConfig } from "@/components/ui/chart"
import { Progress } from "@/components/ui/progress"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Skeleton } from "@/components/ui/skeleton"
import { Table, TableBody, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { api, type Overview, type Ranked } from "@/lib/api"
import { formatHour, formatNumber, formatTime, regionName } from "@/lib/format"
import { Link } from "@/lib/router"
import { useApi } from "@/lib/use-api"

// 只含静态键名与主题变量；接口数据不进入 ChartStyle 注入的样式。
const chartConfig = {
  hits: { label: "命中规则", color: "var(--chart-1)" },
  blocked: { label: "已拦截", color: "var(--chart-2)" },
} satisfies ChartConfig

const RANGES = [
  { value: "24", label: "近 24 小时" },
  { value: "168", label: "近 7 天" },
]

function Kpi({ title, value, hint, action }: { title: string; value?: number; hint: string; action?: React.ReactNode }) {
  return (
    <Card size="sm">
      <CardHeader>
        <CardDescription>{title}</CardDescription>
        <CardTitle className="text-2xl tabular-nums group-data-[size=sm]/card:text-2xl">{value === undefined ? <Skeleton className="h-7 w-16" /> : formatNumber(value)}</CardTitle>
        {action && <CardAction>{action}</CardAction>}
      </CardHeader>
      <CardContent className="text-sm text-muted-foreground">{hint}</CardContent>
    </Card>
  )
}

function RankCard({ title, rows, unit, mono, percent }: { title: string; rows?: Ranked[]; unit: string; mono?: boolean; percent?: boolean }) {
  const total = rows?.reduce((sum, r) => sum + r.count, 0) ?? 0
  return (
    <Card>
      <CardHeader>
        <CardTitle>{title}</CardTitle>
      </CardHeader>
      <CardContent>
        {!rows ? (
          <Skeleton className="h-32 w-full" />
        ) : rows.length === 0 ? (
          <p className="text-sm text-muted-foreground">暂无数据</p>
        ) : (
          <ol className="grid gap-2 text-sm">
            {rows.map((r, i) => (
              <li key={r.key} className="flex items-center gap-2">
                <span className="w-4 text-muted-foreground">{i + 1}</span>
                <span className={mono ? "min-w-0 flex-1 truncate font-mono" : "min-w-0 flex-1 truncate"} title={r.key}>
                  {r.key}
                </span>
                <span className="tabular-nums text-muted-foreground">
                  {percent && total ? `${Math.round((r.count / total) * 100)}%` : `${formatNumber(r.count)} ${unit}`}
                </span>
              </li>
            ))}
          </ol>
        )}
      </CardContent>
    </Card>
  )
}

function RulesCard({ data }: { data?: Overview }) {
  const max = Math.max(1, ...(data?.rules.map((r) => r.hits) ?? [1]))
  return (
    <Card>
      <CardHeader>
        <CardTitle>命中规则分布</CardTitle>
        <CardAction>
          <Link to="/settings" className="text-sm underline-offset-4 hover:underline">
            规则配置
          </Link>
        </CardAction>
      </CardHeader>
      <CardContent className="grid gap-3">
        {!data ? (
          <Skeleton className="h-40 w-full" />
        ) : (
          data.rules.map((r) => (
            <div key={r.id} className="grid gap-1 text-sm">
              <div className="flex justify-between">
                <span>{r.name}</span>
                <span className="tabular-nums text-muted-foreground">{formatNumber(r.hits)}</span>
              </div>
              <Progress value={(r.hits / max) * 100} aria-label={r.name} />
            </div>
          ))
        )}
      </CardContent>
    </Card>
  )
}

export function OverviewPage() {
  const [hours, setHours] = React.useState("24")
  const [incident, setIncident] = React.useState<string | null>(null)
  const { data, error, reload } = useApi(() => api.overview(Number(hours)), [hours])

  return (
    <>
      <div className="flex items-center justify-end">
        <Select value={hours} onValueChange={setHours}>
          <SelectTrigger aria-label="统计时间范围">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {RANGES.map((r) => (
              <SelectItem key={r.value} value={r.value}>
                {r.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      {error ? <LoadError error={error} onRetry={reload} /> : null}

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-5">
        <Kpi title="命中规则的请求" value={data?.kpis.hits} hint="次" />
        <Kpi title="已拦截请求" value={data?.kpis.blocked} hint="次，来自被封禁的访客" />
        <Kpi title="累犯访客" value={data?.kpis.repeat_offenders} hint="个，封禁时长已加长" />
        <Kpi title="新增封禁" value={data?.kpis.new_bans} hint="个访客" />
        <Kpi
          title="当前封禁中"
          value={data?.kpis.active_bans}
          hint="个访客"
          action={
            <Link to="/bans" className="text-sm underline-offset-4 hover:underline">
              查看封禁列表
            </Link>
          }
        />
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle>规则命中与拦截趋势</CardTitle>
            <CardDescription>按小时统计</CardDescription>
          </CardHeader>
          <CardContent>
            {!data ? (
              <Skeleton className="aspect-video w-full" />
            ) : (
              <ChartContainer config={chartConfig} className="aspect-auto h-64 w-full">
                <AreaChart data={data.trend} margin={{ left: 0, right: 8 }}>
                  <CartesianGrid vertical={false} />
                  <XAxis dataKey="hour" tickLine={false} axisLine={false} tickMargin={8} minTickGap={32} tickFormatter={formatHour} />
                  <YAxis tickLine={false} axisLine={false} width={32} allowDecimals={false} />
                  <ChartTooltip content={<ChartTooltipContent labelFormatter={(v) => formatTime(String(v))} />} />
                  <ChartLegend content={<ChartLegendContent />} />
                  <Area dataKey="hits" type="monotone" fill="var(--color-hits)" fillOpacity={0.2} stroke="var(--color-hits)" />
                  <Area dataKey="blocked" type="monotone" fill="var(--color-blocked)" fillOpacity={0.2} stroke="var(--color-blocked)" />
                </AreaChart>
              </ChartContainer>
            )}
          </CardContent>
        </Card>
        <RulesCard data={data} />
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <RankCard title="攻击源 IP 排行" rows={data?.top_ips} unit="次" mono />
        <RankCard title="攻击目标排行" rows={data?.top_targets} unit="次" mono />
        <RankCard title="来源地区排行" rows={data?.top_regions.map((r) => ({ ...r, key: regionName(r.key) }))} unit="次" percent />
      </div>

      <Card>
        <CardHeader>
          <CardTitle>最近攻击事件</CardTitle>
          <CardAction>
            <Link to="/incidents" className="text-sm underline-offset-4 hover:underline">
              查看全部
            </Link>
          </CardAction>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>时间</TableHead>
                <TableHead>攻击 IP</TableHead>
                <TableHead>地区</TableHead>
                <TableHead>触发规则</TableHead>
                <TableHead>命中次数</TableHead>
                <TableHead>处置</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {!data ? (
                <LoadingRows cols={6} rows={5} />
              ) : data.recent.length === 0 ? (
                <EmptyRow cols={6} text="还没有攻击事件" />
              ) : (
                data.recent.map((i) => <IncidentRow key={i.id} incident={i} onOpen={setIncident} />)
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <IncidentSheet id={incident} onClose={() => setIncident(null)} onChanged={reload} />
    </>
  )
}
