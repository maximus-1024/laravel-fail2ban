import { EllipsisIcon } from "lucide-react"
import { Button } from "@/components/ui/button"
import { DropdownMenu, DropdownMenuContent, DropdownMenuTrigger } from "@/components/ui/dropdown-menu"

/**
 * 行内的次要操作：照官方 Data Table 的 Row Actions，「…」按钮打开 DropdownMenu。
 * 菜单在 Portal 里，React 事件仍会冒泡到行；这里拦下，免得点菜单同时触发行点击。
 */
export function RowActions({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex justify-end" onClick={(e) => e.stopPropagation()}>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button variant="ghost" size="icon-sm" aria-label={label}>
            <EllipsisIcon />
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="w-44">
          {children}
        </DropdownMenuContent>
      </DropdownMenu>
    </div>
  )
}
