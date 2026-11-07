import { toast } from "sonner"

/** 复制一段文字并提示；照官方 Data Table 行操作里的 navigator.clipboard.writeText。 */
export function copyText(text: string, what: string) {
  const fail = () => toast.error("复制失败，请手动选中文字复制")
  if (!navigator.clipboard) return fail()
  navigator.clipboard.writeText(text).then(() => toast.success(`已复制${what}`), fail)
}
