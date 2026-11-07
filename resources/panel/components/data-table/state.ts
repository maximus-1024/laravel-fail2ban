import type { ColumnFiltersState, ColumnVisibilityState, OnChangeFn, PaginationState } from "@tanstack/react-table"
import * as React from "react"
import { queryParam, replaceQuery } from "@/lib/router"

/**
 * 一张由接口筛选的表格的状态：搜索词、按列筛选、分页与列显隐。
 * 搜索词进入页面时取地址栏的 ?q=（全局搜索跳转带来的），改了再写回地址栏；筛选或搜索词变化时回到第一页。
 */
export function useTableState(pageSize = 20) {
  const [q, setQ] = React.useState(() => queryParam("q"))
  const [columnFilters, setColumnFilters] = React.useState<ColumnFiltersState>([])
  const [pagination, setPagination] = React.useState<PaginationState>({ pageIndex: 0, pageSize })
  const [columnVisibility, setColumnVisibility] = React.useState<ColumnVisibilityState>({})
  const firstPage = () => setPagination((p) => ({ ...p, pageIndex: 0 }))

  const onColumnFiltersChange: OnChangeFn<ColumnFiltersState> = (updater) => {
    setColumnFilters(updater)
    firstPage()
  }

  return {
    q,
    setQ: (next: string) => {
      setQ(next)
      replaceQuery({ q: next })
      firstPage()
    },
    columnFilters,
    pagination,
    /** 直接展开进 useTable 的选项。 */
    options: {
      state: { columnFilters, pagination, columnVisibility },
      manualFiltering: true,
      onColumnFiltersChange,
      onPaginationChange: setPagination,
      onColumnVisibilityChange: setColumnVisibility,
    },
  }
}
