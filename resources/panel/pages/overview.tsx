import * as React from "react"
import { Area, AreaChart, Bar, BarChart, CartesianGrid, LabelList, XAxis, YAxis } from "recharts"
import { IncidentSheet } from "@/components/incident-sheet"
import { EmptyRow, EmptyState, IncidentRow, LoadError, LoadingRows } from "@/components/shared"
import { Button } from "@/components/ui/button"
import { Card, CardAction, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card"
import { ChartContainer, ChartLegend, ChartLegendContent, ChartTooltip, ChartTooltipContent, type ChartConfig } from "@/components/ui/chart"
import { Item, ItemActions, ItemContent, ItemGroup, ItemMedia, ItemTitle } from "@/components/ui/item"
import { Select, SelectContent, SelectGroup, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Skeleton } from "@/components/ui/skeleton"
import { Table, TableBody, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { api, type Overview, type Ranked } from "@/lib/api"
import { formatHour, formatNumber, formatTime, regionName } from "@/lib/format"
import { Link } from "@/lib/router"
import { useApi } from "@/lib/use-api"

// 只含静态键名与主题变量；接口数据不进入 ChartStyle 注入的样式。
const trendConfig = {
  hits: { label: "命中规则", color: "var(--chart-1)" },
  blocked: { label: "已拦截", color: "var(--chart-2)" },
} satisfies ChartConfig

const rulesConfig = {
  hits: { label: "命中", color: "var(--chart-1)" },
} satisfies ChartConfig

const RANGES = [
  { value: "24", label: "近 24 小时" },
  { value: "168", label: "近 7 天" },
]

function Kpi({ title, value, hint, action }: { title: string; value?: number; hint: string; action?: React.ReactNode }) {
  return (
    <Card>
      <CardHeader>
        <CardDescription>{title}</CardDescription>
        <CardTitle className="text-2xl font-semibold tabular-nums">{value === undefined ? <Skeleton className="h-8 w-16" /> : formatNumber(value)}</CardTitle>
      </CardHeader>
      <CardFooter className="flex-wrap justify-between">
        <CardDescription>{hint}</CardDescription>
        {action}
      </CardFooter>
    </Card>
  )
}

function CardLink({ to, children }: { to: React.ComponentProps<typeof Link>["to"]; children: React.ReactNode }) {
  return (
    <Button variant="outline" size="sm" asChild>
      <Link to={to}>{children}</Link>
    </Button>
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
          <EmptyState />
        ) : (
          <ItemGroup>
            {rows.map((r, i) => (
              <Item key={r.key} size="xs" className="px-0">
                <ItemMedia>{i + 1}</ItemMedia>
                <ItemContent>
                  <ItemTitle className={mono ? "font-mono" : undefined} title={r.key}>
                    {r.key}
                  </ItemTitle>
                </ItemContent>
                <ItemActions>{percent && total ? `${Math.round((r.count / total) * 100)}%` : `${formatNumber(r.count)} ${unit}`}</ItemActions>
              </Item>
            ))}
          </ItemGroup>
        )}
      </CardContent>
    </Card>
  )
}

function RulesCard({ data }: { data?: Overview }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>命中规则分布</CardTitle>
        <CardAction>
          <CardLink to="/settings">规则配置</CardLink>
        </CardAction>
      </CardHeader>
      <CardContent>
        {!data ? (
          <Skeleton className="h-64 w-full" />
        ) : (
          <ChartContainer config={rulesConfig} className="aspect-auto h-64 w-full">
            <BarChart accessibilityLayer data={data.rules} layout="vertical" margin={{ right: 48 }}>
              <XAxis type="number" dataKey="hits" hide />
              <YAxis dataKey="name" type="category" tickLine={false} axisLine={false} tickMargin={8} width={96} />
              <ChartTooltip cursor={false} content={<ChartTooltipContent hideLabel />} />
              <Bar dataKey="hits" fill="var(--color-hits)" radius={4} maxBarSize={16}>
                <LabelList dataKey="hits" position="right" offset={8} className="fill-foreground" fontSize={12} formatter={(v) => formatNumber(Number(v))} />
              </Bar>
            </BarChart>
          </ChartContainer>
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
            <SelectGroup>
              {RANGES.map((r) => (
                <SelectItem key={r.value} value={r.value}>
                  {r.label}
                </SelectItem>
              ))}
            </SelectGroup>
          </SelectContent>
        </Select>
      </div>

      {error ? <LoadError error={error} onRetry={reload} /> : null}

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-5">
        <Kpi title="命中规则的请求" value={data?.kpis.hits} hint="次" />
        <Kpi title="已拦截请求" value={data?.kpis.blocked} hint="次，来自被封禁的访客" />
        <Kpi title="累犯访客" value={data?.kpis.repeat_offenders} hint="个，封禁时长已加长" />
        <Kpi title="新增封禁" value={data?.kpis.new_bans} hint="个访客" />
        <Kpi title="当前封禁中" value={data?.kpis.active_bans} hint="个访客" action={<CardLink to="/bans">查看封禁列表</CardLink>} />
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle>规则命中与拦截趋势</CardTitle>
            <CardDescription>按小时统计</CardDescription>
          </CardHeader>
          <CardContent>
            {!data ? (
              <Skeleton className="h-64 w-full" />
            ) : (
              <ChartContainer config={trendConfig} className="aspect-auto h-64 w-full">
                <AreaChart accessibilityLayer data={data.trend} margin={{ left: 0, right: 8 }}>
                  <CartesianGrid vertical={false} />
                  <XAxis dataKey="hour" tickLine={false} axisLine={false} tickMargin={8} minTickGap={32} tickFormatter={formatHour} />
                  <YAxis tickLine={false} axisLine={false} width={32} allowDecimals={false} />
                  <ChartTooltip cursor={false} content={<ChartTooltipContent indicator="dot" labelFormatter={(v) => formatTime(String(v))} />} />
                  <ChartLegend content={<ChartLegendContent />} />
                  <defs>
                    <linearGradient id="fillHits" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="var(--color-hits)" stopOpacity={0.8} />
                      <stop offset="95%" stopColor="var(--color-hits)" stopOpacity={0.1} />
                    </linearGradient>
                    <linearGradient id="fillBlocked" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="var(--color-blocked)" stopOpacity={0.8} />
                      <stop offset="95%" stopColor="var(--color-blocked)" stopOpacity={0.1} />
                    </linearGradient>
                  </defs>
                  <Area dataKey="hits" type="natural" fill="url(#fillHits)" stroke="var(--color-hits)" />
                  <Area dataKey="blocked" type="natural" fill="url(#fillBlocked)" stroke="var(--color-blocked)" />
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
            <CardLink to="/incidents">查看全部</CardLink>
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
