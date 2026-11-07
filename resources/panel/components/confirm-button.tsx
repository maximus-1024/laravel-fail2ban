import * as React from "react"
import { toast } from "sonner"
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog"
import { Button } from "@/components/ui/button"
import { api, errorMessage } from "@/lib/api"

/** 按钮 + 二次确认：确认后执行 run，成功时提示 success 并关闭，失败时提示原因、对话框留着。 */
export function ConfirmButton({
  label,
  title,
  description,
  confirm,
  success,
  run,
  onDone,
}: {
  label: string
  title: string
  description: string
  confirm: string
  success: string
  run: () => Promise<unknown>
  onDone: () => void
}) {
  const [busy, setBusy] = React.useState(false)
  const [open, setOpen] = React.useState(false)

  async function onConfirm(event: React.MouseEvent) {
    event.preventDefault()
    setBusy(true)
    try {
      await run()
      toast.success(success)
      setOpen(false)
      onDone()
    } catch (error) {
      toast.error(errorMessage(error))
    } finally {
      setBusy(false)
    }
  }

  return (
    <AlertDialog open={open} onOpenChange={setOpen}>
      <AlertDialogTrigger asChild>
        <Button variant="outline" size="sm">
          {label}
        </Button>
      </AlertDialogTrigger>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>{title}</AlertDialogTitle>
          <AlertDialogDescription>{description}</AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel disabled={busy}>取消</AlertDialogCancel>
          <AlertDialogAction variant="destructive" disabled={busy} onClick={onConfirm}>
            {confirm}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  )
}

/** 解封：封禁列表与事件详情共用。 */
export function ConfirmUnban({ visitor, onDone }: { visitor: string; onDone: () => void }) {
  return (
    <ConfirmButton
      label="解封"
      title={`解封 ${visitor}？`}
      description="立即解除封禁，同时清空该访客的命中记录与累犯记录。这次操作会记入操作日志。"
      confirm="确认解封"
      success={`已解封 ${visitor}`}
      run={() => api.unban(visitor)}
      onDone={onDone}
    />
  )
}
