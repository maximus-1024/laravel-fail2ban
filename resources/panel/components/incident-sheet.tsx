import { AllowDialog } from "@/components/allow-dialog"
import { ConfirmUnban } from "@/components/confirm-button"
import { DispositionBadge, EmptyState, LoadError, RuleText } from "@/components/shared"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet"
import { Skeleton } from "@/components/ui/skeleton"
import { Table, TableBody, TableCell, TableHead, TableRow } from "@/components/ui/table"
import { api, type IncidentDetail } from "@/lib/api"
import { formatClock, formatRemaining, formatTime, humanMinutes, regionName } from "@/lib/format"
import { useApi } from "@/lib/use-api"

/** 一行键值：表头列放字段名，值可以换行。 */
function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <TableRow>
      <TableHead scope="row" className="w-24 whitespace-normal">{label}</TableHead>
      <TableCell className="whitespace-normal wrap-anywhere">{children}</TableCell>
    </TableRow>
  )
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <Card size="sm">
      <CardHeader>
        <CardTitle>{title}</CardTitle>
      </CardHeader>
      <CardContent>{children}</CardContent>
    </Card>
  )
}

function Body({ d, onChanged }: { d: IncidentDetail; onChanged: () => void }) {
  const active = d.disposition === "banned" && (d.remaining_seconds ?? 0) > 0
  return (
    <div className="flex flex-col gap-4 px-4 pb-6">
      <div className="flex flex-wrap items-center gap-2">
        <DispositionBadge incident={d} />
        <div className="ml-auto flex gap-2">
          {active && <ConfirmUnban visitor={d.visitor} onDone={onChanged} />}
          <AllowDialog
            entry={d.visitor}
            onDone={onChanged}
            trigger={
              <Button variant="outline" size="sm">
                加入白名单
              </Button>
            }
          />
        </div>
      </div>

      <Section title="触发规则">
        <Table>
          <TableBody>
            <Row label="规则">
              <RuleText incident={d} />
              {d.rule && `，${d.reason ?? "—"}`}
            </Row>
            {d.source === "manual" && d.note && <Row label="备注">{d.note}</Row>}
            {d.ban_minutes != null && (
              <Row label="封禁时长">
                {humanMinutes(d.ban_minutes)}
                {d.offense != null && `，第 ${d.offense} 次被封`}
                {(d.offense ?? 0) > 1 && "，时长已加长"}
              </Row>
            )}
            {d.other_rules.length > 0 && <Row label="同时命中但没到次数">{d.other_rules.map((r) => `${r.name} ${r.count} 次`).join("，")}</Row>}
          </TableBody>
        </Table>
      </Section>

      <Section title="攻击者信息">
        <Table>
          <TableBody>
            <Row label="访客 IP">
              <span className="font-mono">{d.visitor}</span>
            </Row>
            <Row label="国家或地区">{d.region ? regionName(d.region) : "未知"}</Row>
            <Row label="浏览器标识">
              <span className="font-mono">{d.user_agent ?? "—"}</span>
            </Row>
            <Row label="首次命中">{formatTime(d.first_hit_at)}</Row>
            <Row label="触发封禁">{formatTime(d.banned_at ?? d.time)}</Row>
            {d.unban_at && (
              <Row label="解封时间">
                {formatTime(d.unban_at)}
                {active && `，还剩 ${formatRemaining(d.remaining_seconds)}`}
              </Row>
            )}
            {d.blocked != null && (
              <Row label="封禁后被拦">
                {d.blocked} 次{d.last_blocked_at && `，最近一次 ${formatClock(d.last_blocked_at)}`}
              </Row>
            )}
          </TableBody>
        </Table>
      </Section>

      <Section title="请求记录">
        {d.requests.length === 0 ? (
          <EmptyState text="没有请求记录" />
        ) : (
          <Table>
            <TableBody>
              {d.requests.map((r, i) => (
                <TableRow key={i}>
                  <TableCell className="whitespace-normal wrap-anywhere font-mono">
                    {formatClock(r.time)} {r.method ?? ""} {r.path ?? "—"}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </Section>
    </div>
  )
}

/** 事件详情：攻击事件、安全总览、封禁列表共用。id 为 null 时关闭。 */
export function IncidentSheet({ id, onClose, onChanged }: { id: string | null; onClose: () => void; onChanged: () => void }) {
  return (
    <Sheet open={id !== null} onOpenChange={(open) => !open && onClose()}>
      <SheetContent className="w-full overflow-y-auto sm:max-w-xl">
        <SheetHeader>
          <SheetTitle>事件详情</SheetTitle>
          <SheetDescription>{id}</SheetDescription>
        </SheetHeader>
        {id && <Loader id={id} onChanged={onChanged} />}
      </SheetContent>
    </Sheet>
  )
}

function Loader({ id, onChanged }: { id: string; onChanged: () => void }) {
  const { data, error, loading, reload } = useApi(() => api.incident(id), [id])
  if (error && !data)
    return (
      <div className="px-4">
        <LoadError error={error} onRetry={reload} />
      </div>
    )
  if (loading && !data)
    return (
      <div className="flex flex-col gap-3 px-4">
        <Skeleton className="h-5 w-1/3" />
        <Skeleton className="h-24 w-full" />
        <Skeleton className="h-32 w-full" />
      </div>
    )
  if (!data) return null
  return (
    <Body
      d={data}
      onChanged={() => {
        reload()
        onChanged()
      }}
    />
  )
}
