import type { ReactTable, RowData } from "@tanstack/react-table"
import { SearchIcon, XIcon } from "lucide-react"
import * as React from "react"
import { Button } from "@/components/ui/button"
import { InputGroup, InputGroupAddon, InputGroupInput } from "@/components/ui/input-group"
import { DataTableFacetedFilter, type FilterOption } from "./faceted-filter"
import type { Features } from "./features"
import { DataTableViewOptions } from "./view-options"

/** 停止输入多久后才按搜索词请求接口。 */
const SEARCH_DELAY_MS = 300

/**
 * 表格工具栏：照官方 Tasks 示例的 DataTableToolbar 与 shadcn-admin 的 toolbar ——
 * 搜索框、按列筛选、清除筛选，右边是列显隐。搜索词停止输入片刻或按回车后交给接口。
 */
export function DataTableToolbar<TData extends RowData>({
  table,
  search,
  onSearch,
  placeholder,
  filters = [],
}: {
  table: ReactTable<Features, TData>
  /** 已生效的搜索词；不传就不显示搜索框。 */
  search?: string
  onSearch?: (q: string) => void
  placeholder?: string
  filters?: { columnId: string; title: string; options: FilterOption[] }[]
}) {
  const [text, setText] = React.useState(search ?? "")
  const apply = React.useEffectEvent((q: string) => onSearch?.(q))

  // 外面清空了搜索词（清除筛选）时跟着清空输入框
  React.useEffect(() => setText(search ?? ""), [search])
  React.useEffect(() => {
    const q = text.trim()
    if (q === (search ?? "")) return
    const timer = setTimeout(() => apply(q), SEARCH_DELAY_MS)
    return () => clearTimeout(timer)
  }, [text, search])

  const isFiltered = table.state.columnFilters.length > 0 || !!search

  return (
    <div className="flex flex-wrap items-center gap-2">
      {onSearch && (
        <form
          role="search"
          className="w-full sm:w-64"
          onSubmit={(e) => {
            e.preventDefault()
            onSearch(text.trim())
          }}
        >
          <InputGroup>
            <InputGroupInput placeholder={placeholder} aria-label={placeholder} value={text} onChange={(e) => setText(e.target.value)} />
            <InputGroupAddon>
              <SearchIcon />
            </InputGroupAddon>
          </InputGroup>
        </form>
      )}
      {filters.map((f) => {
        const column = table.getColumn(f.columnId)
        return column && <DataTableFacetedFilter key={f.columnId} column={column} title={f.title} options={f.options} />
      })}
      {isFiltered && (
        <Button
          variant="ghost"
          size="sm"
          onClick={() => {
            table.resetColumnFilters(true)
            setText("")
            onSearch?.("")
          }}
        >
          清除筛选
          <XIcon data-icon="inline-end" />
        </Button>
      )}
      <div className="ml-auto">
        <DataTableViewOptions table={table} />
      </div>
    </div>
  )
}
