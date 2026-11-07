import * as React from "react"
import { toast } from "sonner"
import { FieldError } from "@/components/shared"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group"
import { Sheet, SheetContent, SheetDescription, SheetFooter, SheetHeader, SheetTitle } from "@/components/ui/sheet"
import { api, errorMessage, fieldError, type RuleAction, type RuleSetting, type Settings } from "@/lib/api"
import { RULE_ACTIONS, humanMinutes, offenseMinutes } from "@/lib/format"

type Form = { action: RuleAction; window: string; count: string; ban: string }

const toForm = (r: RuleSetting): Form => ({ action: r.action, window: String(r.window_minutes), count: String(r.count), ban: String(r.ban_minutes) })

/** 随输入变化的一句白话。 */
function ruleSummary(rule: RuleSetting, form: Form, repeat: Settings["repeat"]): string {
  if (form.action === "off") return "这条规则已关闭：不统计，也不记录。"
  const win = parseInt(form.window, 10) || 0
  const count = parseInt(form.count, 10) || 0
  const ban = parseInt(form.ban, 10) || 0
  const cond = rule.count_mode === "each" ? `同一访客在 ${win} 分钟内命中 ${count} 次` : `同一访客在 ${win} 分钟内请求了 ${count} 个不同的地址`
  if (form.action === "observe") return `${cond}，只记一条事件，不封禁。`
  let text = `${cond}，封禁 ${humanMinutes(ban)}，到时间自动解封。`
  if (repeat.enabled && ban > 0) text += `累犯加长开启时，第 2 次被封 ${humanMinutes(offenseMinutes(ban, 2, repeat))}。`
  return text
}

export function RuleSheet({
  rule,
  settings,
  onClose,
  onSaved,
}: {
  rule: RuleSetting | null
  settings: Settings
  onClose: () => void
  onSaved: (s: Settings) => void
}) {
  const [form, setForm] = React.useState<Form>({ action: "ban", window: "", count: "", ban: "" })
  const [error, setError] = React.useState<unknown>()
  const [busy, setBusy] = React.useState(false)
  const L = settings.limits

  React.useEffect(() => {
    if (rule) {
      setForm(toForm(rule))
      setError(undefined)
    }
  }, [rule])

  async function submit(event: React.FormEvent) {
    event.preventDefault()
    if (!rule) return
    setBusy(true)
    setError(undefined)
    try {
      const saved = await api.saveSettings({
        rules: [{ id: rule.id, action: form.action, window_minutes: Number(form.window), count: Number(form.count), ban_minutes: Number(form.ban) }],
      })
      toast.success(`已保存「${rule.name}」`)
      onSaved(saved)
      onClose()
    } catch (e) {
      setError(e)
      if (!["action", "window_minutes", "count", "ban_minutes"].some((f) => fieldError(e, `rules.0.${f}`))) toast.error(errorMessage(e))
    } finally {
      setBusy(false)
    }
  }

  const err = (f: string) => fieldError(error, `rules.0.${f}`)
  const ban = parseInt(form.ban, 10) || 0

  return (
    <Sheet open={rule !== null} onOpenChange={(open) => !open && onClose()}>
      <SheetContent className="w-full overflow-y-auto sm:max-w-lg">
        {rule && (
          <form onSubmit={submit} className="flex min-h-full flex-col">
            <SheetHeader>
              <SheetTitle>编辑规则 · {rule.name}</SheetTitle>
              <SheetDescription>{rule.description}</SheetDescription>
            </SheetHeader>
            <div className="grid gap-5 px-4 text-sm">
              <div className="grid gap-3">
                <Label>规则动作</Label>
                <RadioGroup value={form.action} onValueChange={(v) => setForm({ ...form, action: v as RuleAction })}>
                  {(Object.keys(RULE_ACTIONS) as RuleAction[]).map((a) => (
                    <div key={a} className="flex items-start gap-3">
                      <RadioGroupItem value={a} id={`rule-action-${a}`} className="mt-0.5" />
                      <Label htmlFor={`rule-action-${a}`} className="grid gap-1 leading-snug font-normal">
                        <span className="font-medium">{RULE_ACTIONS[a].label}</span>
                        <span className="text-muted-foreground">{RULE_ACTIONS[a].hint}</span>
                      </Label>
                    </div>
                  ))}
                </RadioGroup>
                <FieldError message={err("action")} />
              </div>
              <div className="grid gap-2">
                <Label htmlFor="rule-window">时间范围，单位分钟</Label>
                <Input id="rule-window" type="number" inputMode="numeric" min={L.window_minutes[0]} max={L.window_minutes[1]} value={form.window} aria-invalid={!!err("window_minutes")} onChange={(e) => setForm({ ...form, window: e.target.value })} />
                <p className="text-muted-foreground">从第一次命中算起。可填 {L.window_minutes[0]} 到 {L.window_minutes[1]}。</p>
                <FieldError message={err("window_minutes")} />
              </div>
              <div className="grid gap-2">
                <Label htmlFor="rule-count">出现次数</Label>
                <Input id="rule-count" type="number" inputMode="numeric" min={L.count[0]} max={L.count[1]} value={form.count} aria-invalid={!!err("count")} onChange={(e) => setForm({ ...form, count: e.target.value })} />
                <p className="text-muted-foreground">
                  {rule.count_mode === "each" ? "按请求次数。" : "按不同的地址数。"}可填 {L.count[0]} 到 {L.count[1]}。
                </p>
                <FieldError message={err("count")} />
              </div>
              <div className="grid gap-2">
                <Label htmlFor="rule-ban">封禁时长，单位分钟</Label>
                <Input id="rule-ban" type="number" inputMode="numeric" min={L.ban_minutes[0]} max={L.ban_minutes[1]} value={form.ban} aria-invalid={!!err("ban_minutes")} onChange={(e) => setForm({ ...form, ban: e.target.value })} />
                <p className="text-muted-foreground">
                  {ban > 0 ? `等于 ${humanMinutes(ban)}` : humanMinutes(ban)}。可填 {L.ban_minutes[0]} 到 {L.ban_minutes[1]}。
                </p>
                <FieldError message={err("ban_minutes")} />
              </div>
              <p className="rounded-md border bg-muted/50 p-3" data-testid="rule-summary">
                {ruleSummary(rule, form, settings.repeat)}
              </p>
            </div>
            <SheetFooter className="mt-auto">
              <Button type="submit" disabled={busy}>
                确定
              </Button>
              <Button type="button" variant="outline" onClick={onClose}>
                取消
              </Button>
            </SheetFooter>
          </form>
        )}
      </SheetContent>
    </Sheet>
  )
}
