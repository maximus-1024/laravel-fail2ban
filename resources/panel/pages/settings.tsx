import { InfoIcon, MessageSquareWarningIcon, PowerIcon, RepeatIcon, ShieldCheckIcon } from "lucide-react"
import * as React from "react"
import { toast } from "sonner"
import { PageHeader } from "@/components/page-header"
import { RuleSheet } from "@/components/rule-sheet"
import { CellText, LoadError } from "@/components/shared"
import { useStatus } from "@/components/status"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import { Field, FieldContent, FieldDescription, FieldError, FieldGroup, FieldLabel, FieldLegend, FieldSet } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Item, ItemContent, ItemDescription, ItemTitle } from "@/components/ui/item"
import { Separator } from "@/components/ui/separator"
import { Select, SelectContent, SelectGroup, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Skeleton } from "@/components/ui/skeleton"
import { Spinner } from "@/components/ui/spinner"
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
    <Field data-invalid={!!error}>
      <FieldLabel htmlFor={id}>{label}</FieldLabel>
      <Input id={id} type="number" inputMode="numeric" min={range[0]} max={range[1]} value={value} aria-invalid={!!error} onChange={(e) => onChange(e.target.value)} />
      <FieldDescription>
        {hint}可填 {range[0]} 到 {range[1]}。
      </FieldDescription>
      <FieldError>{error}</FieldError>
    </Field>
  )
}

function Stat({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <Item variant="outline" size="sm">
      <ItemContent>
        <ItemDescription>{label}</ItemDescription>
        <ItemTitle>{value}</ItemTitle>
      </ItemContent>
    </Item>
  )
}

/** 设置页的四个分组：draft 是它在草稿里对应的部分（防护规则在抽屉里逐条保存，没有草稿），fields 是它的 422 字段。 */
const SECTIONS = [
  { id: "mode", title: "运行模式", icon: PowerIcon, draft: "mode", fields: ["mode"], description: "观察模式照常统计与记录，但不拦截；拦截模式才会拒绝被封访客的请求。" },
  { id: "rules", title: "防护规则", icon: ShieldCheckIcon, draft: undefined, fields: [], description: "每条规则单独统计：同一访客在时间范围内达到出现次数，就按这条规则的封禁时长封禁。各规则之间不累加。" },
  { id: "repeat", title: "累犯加长", icon: RepeatIcon, draft: "repeat", fields: ["repeat.factor", "repeat.max_days", "repeat.keep_days"], description: "同一访客解封后不久又被封，封禁时长按倍数加长，到上限为止。对所有规则生效。" },
  { id: "response", title: "拦截响应", icon: MessageSquareWarningIcon, draft: "response", fields: ["response.status", "response.message"], description: "被封访客收到的固定状态码和提示文字。不会告诉访客封禁何时结束。" },
] as const satisfies readonly { id: string; title: string; icon: React.ComponentType<{ className?: string }>; draft: keyof Draft | undefined; fields: readonly string[]; description: string }[]
type SectionId = (typeof SECTIONS)[number]["id"]

/** 一个分组的内容：标题与说明、分隔线，下面是表单。 */
function Section({ section, children }: { section: (typeof SECTIONS)[number]; children: React.ReactNode }) {
  return (
    <FieldSet className="min-w-0">
      <FieldLegend>{section.title}</FieldLegend>
      <FieldDescription>{section.description}</FieldDescription>
      <Separator />
      {children}
    </FieldSet>
  )
}

export function SettingsPage() {
  const { settings, error: loadError, reload, refresh, update } = useStatus()
  // 未保存的修改；undefined 表示没改过，跟着接口的值走
  const [edits, setEdits] = React.useState<Draft>()
  const [error, setError] = React.useState<unknown>()
  const [busy, setBusy] = React.useState(false)
  const [editing, setEditing] = React.useState<RuleSetting | null>(null)
  const [section, setSection] = React.useState<SectionId>("mode")

  // 每次进入本页重取一次（近 24 小时命中、命令行改的设置）；未保存的修改在 edits 里，不会被冲掉
  React.useEffect(refresh, [refresh])

  if (loadError && !settings) return <LoadError error={loadError} onRetry={reload} />
  if (!settings)
    return (
      <div className="flex flex-col gap-4">
        <Skeleton className="h-28 w-full" />
        <Skeleton className="h-72 w-full" />
        <Skeleton className="h-48 w-full" />
      </div>
    )

  const saved = toDraft(settings)
  const draft = edits ?? saved
  const L = settings.limits
  const dirty = JSON.stringify(draft) !== JSON.stringify(saved)
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
      const at = SECTIONS.find((sec) => sec.fields.some((f) => fieldError(e, f)))
      if (at) setSection(at.id)
      toast.error(errorMessage(e))
    } finally {
      setBusy(false)
    }
  }

  const sections = SECTIONS.map((section) => ({ ...section, dirty: section.draft !== undefined && JSON.stringify(draft[section.draft]) !== JSON.stringify(saved[section.draft]) }))

  return (
    <>
      <PageHeader
        title="防护配置"
        description={
          <>
            {dirty ? "运行模式、累犯加长或拦截响应有未保存的修改。" : ""}
            保存后对下一个请求立即生效，每次修改都记入操作日志。
            {settings.updated_at && `上次修改：${settings.updated_by ?? "—"}，${formatTime(settings.updated_at)}。`}
          </>
        }
        actions={
          <>
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
              {busy && <Spinner data-icon="inline-start" />}
              保存修改
            </Button>
          </>
        }
      />

      {/* 照 shadcn-admin 的设置页（src/features/settings/index.tsx 第 59–66 行、components/sidebar-nav.tsx）：
          左边是按钮样式的分组导航，选中项用 secondary 底；窄屏时导航变成顶部的 Select。草稿在本页状态里，切换分组不丢。 */}
      <div className="flex flex-col gap-6 md:flex-row md:gap-10">
        <aside className="shrink-0 md:w-44">
          <Select value={section} onValueChange={(v) => setSection(v as SectionId)}>
            <SelectTrigger className="w-full md:hidden" aria-label="配置分组">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectGroup>
                {sections.map((s) => (
                  <SelectItem key={s.id} value={s.id}>
                    <s.icon />
                    {s.title}
                    {s.dirty && "（未保存）"}
                  </SelectItem>
                ))}
              </SelectGroup>
            </SelectContent>
          </Select>
          <nav className="hidden flex-col gap-1 md:flex" aria-label="配置分组">
            {sections.map((s) => (
              <Button key={s.id} variant={section === s.id ? "secondary" : "ghost"} className="justify-start" aria-current={section === s.id ? "true" : undefined} onClick={() => setSection(s.id)}>
                <s.icon data-icon="inline-start" />
                {s.title}
                {s.dirty && (
                  <Badge variant="outline">
                    未保存
                  </Badge>
                )}
              </Button>
            ))}
          </nav>
        </aside>

        <div className="min-w-0 flex-1">
          {section === "mode" && (
            <Section section={SECTIONS[0]}>
              <Field data-invalid={!!err("mode")}>
                <ToggleGroup type="single" variant="outline" value={draft.mode} onValueChange={(v) => v && setEdits({ ...draft, mode: v as Mode })} aria-label="运行模式">
                  {(Object.keys(MODES) as Mode[]).map((m) => (
                    <ToggleGroupItem key={m} value={m}>
                      {MODES[m]}
                    </ToggleGroupItem>
                  ))}
                </ToggleGroup>
                <FieldError>{err("mode")}</FieldError>
              </Field>
              <div className="grid grid-cols-2 gap-4 sm:grid-cols-3 xl:grid-cols-5">
                <Stat label="规则数" value={settings.rules.length} />
                <Stat label="动作为封禁" value={settings.rules.filter((r) => r.action === "ban").length} />
                <Stat label="每次加长" value={settings.repeat.enabled ? `乘以 ${settings.repeat.factor}` : "已关闭"} />
                <Stat label="最长封禁" value={`${settings.repeat.max_days} 天`} />
                <Stat label="状态码" value={settings.response.status} />
              </div>
            </Section>
          )}

          {section === "rules" && (
            <Section section={SECTIONS[1]}>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>规则</TableHead>
                    <TableHead>动作</TableHead>
                    <TableHead className="text-right">时间范围</TableHead>
                    <TableHead className="text-right">出现次数</TableHead>
                    <TableHead className="text-right">封禁时长</TableHead>
                    <TableHead className="text-right">近 24 小时命中</TableHead>
                    <TableHead>
                      <span className="sr-only">操作</span>
                    </TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {settings.rules.map((r) => (
                    <TableRow key={r.id}>
                      <TableCell className="max-w-80 min-w-56 whitespace-normal">
                        <CellText title={r.name} description={r.description} />
                      </TableCell>
                      <TableCell>
                        <Badge variant={r.action === "ban" ? "default" : r.action === "observe" ? "outline" : "secondary"}>{RULE_ACTIONS[r.action].label}</Badge>
                      </TableCell>
                      <TableCell className="text-right tabular-nums">{r.window_minutes} 分钟</TableCell>
                      <TableCell className="text-right tabular-nums">
                        {r.count} {countUnit(r.count_mode)}
                      </TableCell>
                      <TableCell className="text-right tabular-nums">{humanMinutes(r.ban_minutes)}</TableCell>
                      <TableCell className="text-right tabular-nums">{formatNumber(r.hits_24h)}</TableCell>
                      <TableCell className="text-right">
                        <Button variant="outline" size="sm" onClick={() => setEditing(r)}>
                          编辑
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </Section>
          )}

          {section === "repeat" && (
            <Section section={SECTIONS[2]}>
              <FieldGroup>
                <Field orientation="horizontal">
                  <Switch id="repeat-enabled" checked={draft.repeat.enabled} onCheckedChange={(enabled) => setRepeat({ enabled })} />
                  <FieldContent>
                    <FieldLabel htmlFor="repeat-enabled">开启累犯加长</FieldLabel>
                    <FieldDescription>关闭后，每次被封都按规则自己的封禁时长。</FieldDescription>
                  </FieldContent>
                </Field>
                <div className="grid gap-4 lg:grid-cols-3">
                  <NumberField id="repeat-factor" label="加长倍数" hint="每多被封一次，时长乘以这个数。" range={L.factor} value={draft.repeat.factor} error={err("repeat.factor")} onChange={(factor) => setRepeat({ factor })} />
                  <NumberField id="repeat-max" label="最长封禁，单位天" hint="加长到这个时长为止。" range={L.max_days} value={draft.repeat.max_days} error={err("repeat.max_days")} onChange={(max_days) => setRepeat({ max_days })} />
                  <NumberField id="repeat-keep" label="累犯记录保留，单位天" hint="解封后这么多天没有再被封，就重新从第 1 次算。" range={L.keep_days} value={draft.repeat.keep_days} error={err("repeat.keep_days")} onChange={(keep_days) => setRepeat({ keep_days })} />
                </div>
                <Alert>
                  <InfoIcon />
                  <AlertDescription>{repeatExample(draft.repeat, settings.rules)}</AlertDescription>
                </Alert>
              </FieldGroup>
            </Section>
          )}

          {section === "response" && (
            <Section section={SECTIONS[3]}>
              <FieldGroup className="max-w-xl">
                <Field data-invalid={!!err("response.status")}>
                  <FieldLabel htmlFor="response-status">返回的状态码</FieldLabel>
                  <Select value={draft.response.status} onValueChange={(v) => setResponse({ status: v })}>
                    <SelectTrigger id="response-status" className="w-full sm:w-56" aria-invalid={!!err("response.status")}>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectGroup>
                        {statuses.map((code) => (
                          <SelectItem key={code} value={String(code)}>
                            {`${code} ${STATUS_NAMES[code] ?? ""}`.trim()}
                          </SelectItem>
                        ))}
                      </SelectGroup>
                    </SelectContent>
                  </Select>
                  <FieldDescription>被封访客的每个请求都固定返回这一个状态码。</FieldDescription>
                  <FieldError>{err("response.status")}</FieldError>
                </Field>
                <Field data-invalid={!!err("response.message")}>
                  <FieldLabel htmlFor="response-message">给访客的提示文字</FieldLabel>
                  <Textarea id="response-message" rows={3} maxLength={L.message?.[1]} value={draft.response.message} aria-invalid={!!err("response.message")} onChange={(e) => setResponse({ message: e.target.value })} />
                  {L.message && <FieldDescription>最多 {L.message[1]} 个字。</FieldDescription>}
                  <FieldError>{err("response.message")}</FieldError>
                </Field>
                <FieldSet>
                  <FieldLegend variant="label">随提示一起显示</FieldLegend>
                  <FieldGroup data-slot="checkbox-group">
                    {(
                      [
                        ["show_ip", "访客 IP"],
                        ["show_incident", "事件编号"],
                        ["show_time", "记录时间"],
                      ] as const
                    ).map(([key, label]) => (
                      <Field key={key} orientation="horizontal">
                        <Checkbox id={`response-${key}`} checked={draft.response[key]} onCheckedChange={(v) => setResponse({ [key]: v === true })} />
                        <FieldLabel htmlFor={`response-${key}`}>{label}</FieldLabel>
                      </Field>
                    ))}
                  </FieldGroup>
                </FieldSet>
              </FieldGroup>
            </Section>
          )}
        </div>
      </div>

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
