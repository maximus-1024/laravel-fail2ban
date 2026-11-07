import {
  columnFilteringFeature,
  columnVisibilityFeature,
  createPaginatedRowModel,
  filterFn_arrIncludesSome,
  metaHelper,
  rowPaginationFeature,
  tableFeatures,
  type ColumnFiltersState,
} from "@tanstack/react-table"

/**
 * 照官方 Data Table（TanStack Table v9）的写法声明用到的功能。
 * 筛选一律交给接口（manualFiltering），分页按接口能力：攻击事件与操作日志由接口分页（manualPagination），
 * 封禁列表接口一次返回全部，用本地分页模型分页。
 */
export const features = tableFeatures({
  columnFilteringFeature,
  columnVisibilityFeature,
  rowPaginationFeature,
  paginatedRowModel: createPaginatedRowModel(),
  // 列的 filterFn 用它：筛选值是数组，空数组时自动去掉这一项（照官方 faceted filter）
  filterFns: { arrIncludesSome: filterFn_arrIncludesSome },
  columnMeta: metaHelper<{
    /** 列显隐下拉里显示的列名。 */
    label?: string
    /** 表头与单元格共用的布局类，例如数字列的 text-right tabular-nums。 */
    className?: string
  }>(),
})

export type Features = typeof features

/** 某一列当前选中的筛选值（接口每个筛选只接一个值，取第一个）。 */
export function filterValue(filters: ColumnFiltersState, id: string): string | undefined {
  const value = filters.find((f) => f.id === id)?.value
  return Array.isArray(value) && typeof value[0] === "string" ? value[0] : undefined
}
