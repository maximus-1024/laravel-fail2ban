import * as React from "react"
import { toast } from "sonner"
import { RuleSheet } from "@/components/rule-sheet"
import { FieldError, LoadError } from "@/components/shared"
import { useStatus } from "@/components/status"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card"
import { Checkbox } from "@/components/ui/checkbox"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Skeleton } from "@/components/ui/skeleton"
import { Switch } from "@/components/ui/switch"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Textarea } from "@/components/ui/textarea"
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group"
import { api, errorMessage, fieldError, type Mode, type Range, type RuleSetting, type Settings } from "@/lib/api"
import { MODES, RULE_ACTIONS, countUnit, formatNumber, formatTime, humanMinutes, offenseMinutes } from "@/lib/format"

const STATUS_NAMES: Record<number, string> = { 403: "禁止访问", 429: "请求过多", 404: "不存在" }

interface Draft {
  mode: Mode
  repeat: { enabled: boolean; factor: string; max_days: string; keep_days: string }
  response: { status: string; message: string; show_ip: boolean; show_incident: boolean; show_time: boolean }
}

function toDraft(s: Settings): Draft {
  return {
    mode: s.mode,
    repeat: { enabled: s.repeat.enabled, factor: String(s.repeat.factor), max_days: String(s.repeat.max_days), keep_days: String(s.repeat.keep_days) },
    response: { ...s.response, status: String(s.response.status) },
  }
}

/** 累犯加长的例子：以规则列表的第一条（接口返回的顺序）为起点。 */
function repeatExample(draft: Draft["repeat"], rules: RuleSetting[]): string {
  if (!draft.enabled) return "累犯加长已关闭：每次被封都按规则自己的封禁时长。"
  const base = rules[0]
  const repeat = { enabled: true, factor: parseInt(draft.factor, 10) || 0, max_days: parseInt(draft.max_days, 10) || 0 }
  const keepDays = parseInt(draft.keep_days, 10) || 0
  if (!base || repeat.factor < 1 || repeat.max_days < 1) return "填好加长倍数与最长封禁后，这里会给出例子。"
  const steps = [1, 2, 3, 4].map((n) => `第 ${n} 次封 ${humanMinutes(offenseMinutes(base.ban_minutes, n, repeat))}`)
  return `以${base.name}为例：${steps.join("，")}，最长 ${repeat.max_days} 天。解封后 ${keepDays} 天内没有再被封，重新从第 1 次算。`
}

function NumberField({ id, label, hint, range, value, error, onChange }: { id: string; label: string; hint: string; range: Range; value: string; error?: string; onChange: (v: string) => void }) {
  return (
    <div className="grid gap-2">
      <Label htmlFor={id}>{label}</Label>
      <Input id={id} type="number" inputMode="numeric" min={range[0]} max={range[1]} value={value} aria-invalid={!!error} onChange={(e) => onChange(e.target.value)} />
      <p className="text-sm text-muted-foreground">
        {hint}可填 {range[0]} 到 {range[1]}。
      </p>
      <FieldError message={error} />
    </div>
  )
}

function Stat({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="grid gap-0.5">
      <span className="text-sm text-muted-foreground">{label}</span>
      <span className="text-lg font-medium">{value}</span>
    </div>
  )
}

export function SettingsPage() {
  const { settings, error: loadError, reload, refresh, update } = useStatus()
  // 未保存的修改；undefined 表示没改过，跟着接口的值走
  const [edits, setEdits] = React.useState<Draft>()
  const [error, setError] = React.useState<unknown>()
  const [busy, setBusy] = React.useState(false)
  const [editing, setEditing] = React.useState<RuleSetting | null>(null)

  // 每次进入本页重取一次（近 24 小时命中、命令行改的设置）；未保存的修改在 edits 里，不会被冲掉
  React.useEffect(refresh, [refresh])

  if (loadError && !settings) return <LoadError error={loadError} onRetry={reload} />
  if (!settings)
    return (
      <div className="grid gap-4">
        <Skeleton className="h-28 w-full" />
        <Skeleton className="h-72 w-full" />
        <Skeleton className="h-48 w-full" />
      </div>
    )

  const draft = edits ?? toDraft(settings)
  const L = settings.limits
  const dirty = JSON.stringify(draft) !== JSON.stringify(toDraft(settings))
  const err = (f: string) => fieldError(error, f)
  const setRepeat = (patch: Partial<Draft["repeat"]>) => setEdits({ ...draft, repeat: { ...draft.repeat, ...patch } })
  const setResponse = (patch: Partial<Draft["response"]>) => setEdits({ ...draft, response: { ...draft.response, ...patch } })
  const statuses = L.statuses.includes(Number(draft.response.status)) ? L.statuses : [...L.statuses, Number(draft.response.status)]

  async function save() {
    setBusy(true)
    setError(undefined)
    try {
      const saved = await api.saveSettings({
        mode: draft.mode,
        repeat: {
          enabled: draft.repeat.enabled,
          factor: Number(draft.repeat.factor),
          max_days: Number(draft.repeat.max_days),
          keep_days: Number(draft.repeat.keep_days),
        },
        response: { ...draft.response, status: Number(draft.response.status) },
      })
      update(saved)
      setEdits(undefined)
      toast.success("防护配置已保存")
    } catch (e) {
      setError(e)
      toast.error(errorMessage(e))
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <Card>
        <CardHeader>
          <CardTitle>运行模式</CardTitle>
          <CardDescription>观察模式照常统计与记录，但不拦截；拦截模式才会拒绝被封访客的请求。</CardDescription>
        </CardHeader>
        <CardContent className="grid gap-4">
          <ToggleGroup type="single" variant="outline" value={draft.mode} onValueChange={(v) => v && setEdits({ ...draft, mode: v as Mode })} aria-label="运行模式">
            {(Object.keys(MODES) as Mode[]).map((m) => (
              <ToggleGroupItem key={m} value={m}>
                {MODES[m]}
              </ToggleGroupItem>
            ))}
          </ToggleGroup>
          <FieldError message={err("mode")} />
          <div className="grid grid-cols-2 gap-4 sm:grid-cols-5">
            <Stat label="规则数" value={settings.rules.length} />
            <Stat label="动作为封禁" value={settings.rules.filter((r) => r.action === "ban").length} />
            <Stat label="每次加长" value={settings.repeat.enabled ? `乘以 ${settings.repeat.factor}` : "已关闭"} />
            <Stat label="最长封禁" value={`${settings.repeat.max_days} 天`} />
            <Stat label="状态码" value={settings.response.status} />
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>防护规则</CardTitle>
          <CardDescription>每条规则单独统计：同一访客在时间范围内达到出现次数，就按这条规则的封禁时长封禁。各规则之间不累加。</CardDescription>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>规则</TableHead>
                <TableHead>动作</TableHead>
                <TableHead>时间范围</TableHead>
                <TableHead>出现次数</TableHead>
                <TableHead>封禁时长</TableHead>
                <TableHead>近 24 小时命中</TableHead>
                <TableHead>操作</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {settings.rules.map((r) => (
                <TableRow key={r.id}>
                  <TableCell className="max-w-80 min-w-56 whitespace-normal">
                    <div className="font-medium">{r.name}</div>
                    <div className="text-xs text-muted-foreground">{r.description}</div>
                  </TableCell>
                  <TableCell>
                    <Badge variant={r.action === "ban" ? "default" : r.action === "observe" ? "secondary" : "outline"}>{RULE_ACTIONS[r.action].label}</Badge>
                  </TableCell>
                  <TableCell>{r.window_minutes} 分钟</TableCell>
                  <TableCell>
                    {r.count} {countUnit(r.count_mode)}
                  </TableCell>
                  <TableCell>{humanMinutes(r.ban_minutes)}</TableCell>
                  <TableCell className="tabular-nums">{formatNumber(r.hits_24h)}</TableCell>
                  <TableCell>
                    <Button variant="outline" size="sm" onClick={() => setEditing(r)}>
                      编辑
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>累犯加长</CardTitle>
          <CardDescription>同一访客解封后不久又被封，封禁时长按倍数加长，到上限为止。对所有规则生效。</CardDescription>
        </CardHeader>
        <CardContent className="grid gap-4">
          <div className="flex items-center gap-3">
            <Switch id="repeat-enabled" checked={draft.repeat.enabled} onCheckedChange={(enabled) => setRepeat({ enabled })} />
            <Label htmlFor="repeat-enabled" className="grid gap-1 leading-snug">
              <span>开启累犯加长</span>
              <span className="font-normal text-muted-foreground">关闭后，每次被封都按规则自己的封禁时长。</span>
            </Label>
          </div>
          <div className="grid gap-4 md:grid-cols-3">
            <NumberField id="repeat-factor" label="加长倍数" hint="每多被封一次，时长乘以这个数。" range={L.factor} value={draft.repeat.factor} error={err("repeat.factor")} onChange={(factor) => setRepeat({ factor })} />
            <NumberField id="repeat-max" label="最长封禁，单位天" hint="加长到这个时长为止。" range={L.max_days} value={draft.repeat.max_days} error={err("repeat.max_days")} onChange={(max_days) => setRepeat({ max_days })} />
            <NumberField id="repeat-keep" label="累犯记录保留，单位天" hint="解封后这么多天没有再被封，就重新从第 1 次算。" range={L.keep_days} value={draft.repeat.keep_days} error={err("repeat.keep_days")} onChange={(keep_days) => setRepeat({ keep_days })} />
          </div>
          <p className="rounded-md border bg-muted/50 p-3 text-sm">{repeatExample(draft.repeat, settings.rules)}</p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>拦截响应</CardTitle>
          <CardDescription>被封访客收到的固定状态码和提示文字。不会告诉访客封禁何时结束。</CardDescription>
        </CardHeader>
        <CardContent className="grid gap-4">
          <div className="grid gap-2">
            <Label htmlFor="response-status">返回的状态码</Label>
            <Select value={draft.response.status} onValueChange={(v) => setResponse({ status: v })}>
              <SelectTrigger id="response-status" className="w-full sm:w-56">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {statuses.map((code) => (
                  <SelectItem key={code} value={String(code)}>
                    {`${code} ${STATUS_NAMES[code] ?? ""}`.trim()}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <p className="text-sm text-muted-foreground">被封访客的每个请求都固定返回这一个状态码。</p>
            <FieldError message={err("response.status")} />
          </div>
          <div className="grid gap-2">
            <Label htmlFor="response-message">给访客的提示文字</Label>
            <Textarea id="response-message" rows={3} maxLength={L.message?.[1]} value={draft.response.message} aria-invalid={!!err("response.message")} onChange={(e) => setResponse({ message: e.target.value })} />
            {L.message && <p className="text-sm text-muted-foreground">最多 {L.message[1]} 个字。</p>}
            <FieldError message={err("response.message")} />
          </div>
          <fieldset className="grid gap-3">
            <legend className="mb-2 text-sm font-medium">随提示一起显示</legend>
            <div className="flex flex-wrap gap-6">
              {(
                [
                  ["show_ip", "访客 IP"],
                  ["show_incident", "事件编号"],
                  ["show_time", "记录时间"],
                ] as const
              ).map(([key, label]) => (
                <div key={key} className="flex items-center gap-2">
                  <Checkbox id={`response-${key}`} checked={draft.response[key]} onCheckedChange={(v) => setResponse({ [key]: v === true })} />
                  <Label htmlFor={`response-${key}`} className="font-normal">
                    {label}
                  </Label>
                </div>
              ))}
            </div>
          </fieldset>
        </CardContent>
      </Card>

      <Card size="sm">
        <CardFooter className="flex flex-wrap items-center gap-3">
          <p className="mr-auto text-sm text-muted-foreground">
            {dirty ? "运行模式、累犯加长或拦截响应有未保存的修改。" : ""}
            保存后对下一个请求立即生效，每次修改都记入操作日志。
            {settings.updated_at && `上次修改：${settings.updated_by ?? "—"}，${formatTime(settings.updated_at)}。`}
          </p>
          <Button
            variant="outline"
            disabled={!dirty || busy}
            onClick={() => {
              setEdits(undefined)
              setError(undefined)
            }}
          >
            放弃修改
          </Button>
          <Button disabled={!dirty || busy} onClick={save}>
            保存修改
          </Button>
        </CardFooter>
      </Card>

      <RuleSheet
        rule={editing}
        settings={settings}
        onClose={() => setEditing(null)}
        // 未保存的运行模式、累犯加长与拦截响应修改在 edits 里，不受影响
        onSaved={update}
      />
    </>
  )
}
