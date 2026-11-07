import { AllowDialog } from "@/components/allow-dialog"
import { ConfirmUnban } from "@/components/confirm-button"
import { DispositionBadge, LoadError, RuleText } from "@/components/shared"
import { Button } from "@/components/ui/button"
import { Separator } from "@/components/ui/separator"
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet"
import { Skeleton } from "@/components/ui/skeleton"
import { api, type IncidentDetail } from "@/lib/api"
import { formatClock, formatRemaining, formatTime, humanMinutes, regionName } from "@/lib/format"
import { useApi } from "@/lib/use-api"

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="grid grid-cols-[7rem_1fr] gap-2 py-1">
      <dt className="text-muted-foreground">{label}</dt>
      <dd className="min-w-0 break-all">{children}</dd>
    </div>
  )
}

function Body({ d, onChanged }: { d: IncidentDetail; onChanged: () => void }) {
  const active = d.disposition === "banned" && (d.remaining_seconds ?? 0) > 0
  return (
    <div className="grid gap-4 px-4 pb-6 text-sm">
      <div className="flex flex-wrap items-center gap-2">
        <DispositionBadge incident={d} />
        <span className="ml-auto flex gap-2">
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
        </span>
      </div>

      <section className="grid gap-1">
        <h3 className="font-medium">触发规则</h3>
        <dl>
          <Field label="规则">
            <RuleText incident={d} />
            {d.rule && `，${d.reason ?? "—"}`}
          </Field>
          {d.source === "manual" && d.note && <Field label="备注">{d.note}</Field>}
          {d.ban_minutes != null && (
            <Field label="封禁时长">
              {humanMinutes(d.ban_minutes)}
              {d.offense != null && `，第 ${d.offense} 次被封`}
              {(d.offense ?? 0) > 1 && "，时长已加长"}
            </Field>
          )}
          {d.other_rules.length > 0 && (
            <Field label="同时命中但没到次数">{d.other_rules.map((r) => `${r.name} ${r.count} 次`).join("，")}</Field>
          )}
        </dl>
      </section>

      <Separator />

      <section className="grid gap-1">
        <h3 className="font-medium">攻击者信息</h3>
        <dl>
          <Field label="访客 IP">
            <span className="font-mono">{d.visitor}</span>
          </Field>
          <Field label="国家或地区">{d.region ? regionName(d.region) : "未知"}</Field>
          <Field label="浏览器标识">
            <span className="font-mono">{d.user_agent ?? "—"}</span>
          </Field>
          <Field label="首次命中">{formatTime(d.first_hit_at)}</Field>
          <Field label="触发封禁">{formatTime(d.banned_at ?? d.time)}</Field>
          {d.unban_at && (
            <Field label="解封时间">
              {formatTime(d.unban_at)}
              {active && `，还剩 ${formatRemaining(d.remaining_seconds)}`}
            </Field>
          )}
          {d.blocked != null && (
            <Field label="封禁后被拦">
              {d.blocked} 次{d.last_blocked_at && `，最近一次 ${formatClock(d.last_blocked_at)}`}
            </Field>
          )}
        </dl>
      </section>

      <Separator />

      <section className="grid gap-2">
        <h3 className="font-medium">请求记录</h3>
        {d.requests.length === 0 ? (
          <p className="text-muted-foreground">没有请求记录</p>
        ) : (
          <ol className="grid gap-2">
            {d.requests.map((r, i) => (
              <li key={i} className="grid gap-0.5 rounded-md border p-2">
                <span className="font-mono text-xs break-all">
                  {formatClock(r.time)} {r.method ?? ""} {r.path ?? "—"}
                </span>
              </li>
            ))}
          </ol>
        )}
      </section>
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
          <SheetDescription className="font-mono">{id}</SheetDescription>
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
      <div className="grid gap-3 px-4">
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
