import * as React from "react"
import { toast } from "sonner"
import { FieldError } from "@/components/shared"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Textarea } from "@/components/ui/textarea"
import { api, errorMessage, fieldError } from "@/lib/api"

const DURATIONS = [
  { value: "30", label: "30 分钟" },
  { value: "120", label: "2 小时" },
  { value: "1440", label: "24 小时" },
  { value: "custom", label: "自定义" },
]

export function BanDialog({ onDone }: { onDone: () => void }) {
  const empty = { ip: "", duration: "120", custom: "", note: "" }
  const [open, setOpen] = React.useState(false)
  const [form, setForm] = React.useState(empty)
  const [error, setError] = React.useState<unknown>()
  const [busy, setBusy] = React.useState(false)

  function onOpenChange(next: boolean) {
    setOpen(next)
    if (next) {
      setForm(empty)
      setError(undefined)
    }
  }

  async function submit(event: React.FormEvent) {
    event.preventDefault()
    setBusy(true)
    setError(undefined)
    const minutes = Number(form.duration === "custom" ? form.custom : form.duration)
    try {
      const ban = await api.ban({ ip: form.ip.trim(), minutes, note: form.note.trim() })
      toast.success(`已封禁 ${ban.visitor}`)
      setOpen(false)
      onDone()
    } catch (e) {
      setError(e)
      if (!["ip", "minutes", "note"].some((f) => fieldError(e, f))) toast.error(errorMessage(e))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogTrigger asChild>
        <Button>手动封禁</Button>
      </DialogTrigger>
      <DialogContent>
        <form onSubmit={submit} className="grid gap-4">
          <DialogHeader>
            <DialogTitle>手动封禁</DialogTitle>
            <DialogDescription>有两类地址不能手动封：白名单里的地址，和宿主程序豁免的地址。提交时会检查并提示。</DialogDescription>
          </DialogHeader>
          <div className="grid gap-2">
            <Label htmlFor="ban-ip">IP 地址</Label>
            <Input
              id="ban-ip"
              value={form.ip}
              placeholder="203.0.113.47"
              aria-invalid={!!fieldError(error, "ip")}
              onChange={(e) => setForm({ ...form, ip: e.target.value })}
            />
            <p className="text-sm text-muted-foreground">IPv6 会按前 64 位网段封禁。</p>
            <FieldError message={fieldError(error, "ip")} />
          </div>
          <div className="grid gap-2">
            <Label htmlFor="ban-duration">封禁时长</Label>
            <Select value={form.duration} onValueChange={(duration) => setForm({ ...form, duration })}>
              <SelectTrigger id="ban-duration" className="w-full">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {DURATIONS.map((d) => (
                  <SelectItem key={d.value} value={d.value}>
                    {d.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            {form.duration === "custom" && (
              <Input
                type="number"
                inputMode="numeric"
                min={1}
                placeholder="分钟数"
                aria-label="自定义封禁时长，单位分钟"
                value={form.custom}
                aria-invalid={!!fieldError(error, "minutes")}
                onChange={(e) => setForm({ ...form, custom: e.target.value })}
              />
            )}
            <FieldError message={fieldError(error, "minutes")} />
          </div>
          <div className="grid gap-2">
            <Label htmlFor="ban-note">备注，必填</Label>
            <Textarea
              id="ban-note"
              rows={3}
              value={form.note}
              placeholder="为什么封它"
              aria-invalid={!!fieldError(error, "note")}
              onChange={(e) => setForm({ ...form, note: e.target.value })}
            />
            <p className="text-sm text-muted-foreground">会显示在封禁列表和操作日志里。</p>
            <FieldError message={fieldError(error, "note")} />
          </div>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => setOpen(false)}>
              取消
            </Button>
            <Button type="submit" variant="destructive" disabled={busy}>
              确认封禁
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
