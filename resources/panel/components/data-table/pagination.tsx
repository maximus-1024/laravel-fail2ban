import type { ReactTable, RowData } from "@tanstack/react-table"
import * as React from "react"
import { ChevronLeftIcon, ChevronRightIcon, ChevronsLeftIcon, ChevronsRightIcon } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Field, FieldLabel } from "@/components/ui/field"
import { Select, SelectContent, SelectGroup, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import type { Features } from "./features"

/** 每页条数的可选值；接口的 per_page 上限是 100。 */
const PAGE_SIZES = [10, 20, 50, 100]

/**
 * 底部分页：照官方 Tasks 示例的 DataTablePagination —— 左边是条数说明，右边是每页条数、页码与翻页按钮。
 */
export function DataTablePagination<TData extends RowData>({ table, summary }: { table: ReactTable<Features, TData>; summary: React.ReactNode }) {
  const { pageIndex, pageSize } = table.state.pagination
  const pages = Math.max(1, table.getPageCount())
  const id = React.useId()
  return (
    <div className="flex w-full flex-wrap items-center justify-between gap-4">
      <div className="flex-1">{summary}</div>
      <div className="flex flex-wrap items-center gap-4 lg:gap-6">
        <Field orientation="horizontal" className="w-fit">
          <FieldLabel htmlFor={id} className="whitespace-nowrap">
            每页
          </FieldLabel>
          <Select value={String(pageSize)} onValueChange={(v) => table.setPageSize(Number(v))}>
            <SelectTrigger id={id} size="sm">
              <SelectValue />
            </SelectTrigger>
            <SelectContent side="top">
              <SelectGroup>
                {PAGE_SIZES.map((size) => (
                  <SelectItem key={size} value={String(size)}>
                    {size} 条
                  </SelectItem>
                ))}
              </SelectGroup>
            </SelectContent>
          </Select>
        </Field>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="icon-sm" className="hidden lg:inline-flex" aria-label="第一页" disabled={!table.getCanPreviousPage()} onClick={() => table.setPageIndex(0)}>
            <ChevronsLeftIcon />
          </Button>
          <Button variant="outline" size="icon-sm" aria-label="上一页" disabled={!table.getCanPreviousPage()} onClick={() => table.previousPage()}>
            <ChevronLeftIcon />
          </Button>
          <span className="tabular-nums whitespace-nowrap" aria-live="polite">
            第 {pageIndex + 1} / {pages} 页
          </span>
          <Button variant="outline" size="icon-sm" aria-label="下一页" disabled={!table.getCanNextPage()} onClick={() => table.nextPage()}>
            <ChevronRightIcon />
          </Button>
          <Button variant="outline" size="icon-sm" className="hidden lg:inline-flex" aria-label="最后一页" disabled={!table.getCanNextPage()} onClick={() => table.setPageIndex(pages - 1)}>
            <ChevronsRightIcon />
          </Button>
        </div>
      </div>
    </div>
  )
}
