import * as React from "react"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog"
import { Field, FieldError, FieldGroup, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Spinner } from "@/components/ui/spinner"
import { api, errorMessage, fieldError } from "@/lib/api"

/** 加入白名单对话框：白名单页的「添加」与事件详情里的「加入白名单」共用。 */
export function AllowDialog({ entry = "", trigger, onDone }: { entry?: string; trigger: React.ReactNode; onDone: () => void }) {
  const [open, setOpen] = React.useState(false)
  const [form, setForm] = React.useState({ entry, note: "" })
  const [error, setError] = React.useState<unknown>()
  const [busy, setBusy] = React.useState(false)

  function onOpenChange(next: boolean) {
    setOpen(next)
    if (next) {
      setForm({ entry, note: "" })
      setError(undefined)
    }
  }

  async function submit(event: React.FormEvent) {
    event.preventDefault()
    setBusy(true)
    setError(undefined)
    try {
      const row = await api.allow({ entry: form.entry.trim(), note: form.note.trim() })
      toast.success(`已把 ${row.entry} 加入白名单`)
      setOpen(false)
      onDone()
    } catch (e) {
      setError(e)
      if (!fieldError(e, "entry") && !fieldError(e, "note")) toast.error(errorMessage(e))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogTrigger asChild>{trigger}</DialogTrigger>
      <DialogContent>
        <form onSubmit={submit} className="flex flex-col gap-6">
          <DialogHeader>
            <DialogTitle>加入白名单</DialogTitle>
            <DialogDescription>白名单里的 IP 和网段不统计命中，也不会被封。加入时会同时解除它当前的封禁。</DialogDescription>
          </DialogHeader>
          <FieldGroup>
            <Field data-invalid={!!fieldError(error, "entry")}>
              <FieldLabel htmlFor="allow-entry">IP 或网段</FieldLabel>
              <Input
                id="allow-entry"
                value={form.entry}
                placeholder="203.0.113.10 或 198.51.100.0/28"
                aria-invalid={!!fieldError(error, "entry")}
                onChange={(e) => setForm({ ...form, entry: e.target.value })}
              />
              <FieldError>{fieldError(error, "entry")}</FieldError>
            </Field>
            <Field data-invalid={!!fieldError(error, "note")}>
              <FieldLabel htmlFor="allow-note">备注</FieldLabel>
              <Input
                id="allow-note"
                value={form.note}
                placeholder="写清楚这是谁的地址"
                aria-invalid={!!fieldError(error, "note")}
                onChange={(e) => setForm({ ...form, note: e.target.value })}
              />
              <FieldError>{fieldError(error, "note")}</FieldError>
            </Field>
          </FieldGroup>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => setOpen(false)}>
              取消
            </Button>
            <Button type="submit" disabled={busy || !form.entry.trim()}>
              {busy && <Spinner data-icon="inline-start" />}
              添加
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
