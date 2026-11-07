import type { ReactTable, RowData } from "@tanstack/react-table"
import { EmptyState } from "@/components/shared"
import { Skeleton } from "@/components/ui/skeleton"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import type { Features } from "./features"

/**
 * 表格本体：照官方 Data Table 的 <DataTable />，表头与单元格交给列定义渲染。
 * 首次加载显示 Skeleton 行；没有数据显示 Empty。
 */
export function DataTable<TData extends RowData>({
  table,
  loading,
  empty,
  skeletonRows = 5,
  onRowClick,
}: {
  table: ReactTable<Features, TData>
  /** 还没有任何数据时为 true。 */
  loading: boolean
  empty: string
  skeletonRows?: number
  onRowClick?: (row: TData) => void
}) {
  const columns = table.getVisibleLeafColumns()
  const rows = table.getRowModel().rows
  return (
    <Table>
      <TableHeader>
        {table.getHeaderGroups().map((group) => (
          <TableRow key={group.id}>
            {group.headers.map((header) => (
              <TableHead key={header.id} colSpan={header.colSpan} className={header.column.columnDef.meta?.className}>
                {header.isPlaceholder ? null : <table.FlexRender header={header} />}
              </TableHead>
            ))}
          </TableRow>
        ))}
      </TableHeader>
      <TableBody>
        {loading ? (
          Array.from({ length: skeletonRows }, (_, r) => (
            <TableRow key={r}>
              {columns.map((c) => (
                <TableCell key={c.id}>
                  <Skeleton className="h-4 w-full" />
                </TableCell>
              ))}
            </TableRow>
          ))
        ) : rows.length ? (
          rows.map((row) => (
            <TableRow key={row.id} className={onRowClick ? "cursor-pointer" : undefined} onClick={onRowClick && (() => onRowClick(row.original))}>
              {row.getVisibleCells().map((cell) => (
                <TableCell key={cell.id} className={cell.column.columnDef.meta?.className}>
                  <table.FlexRender cell={cell} />
                </TableCell>
              ))}
            </TableRow>
          ))
        ) : (
          <TableRow>
            <TableCell colSpan={columns.length}>
              <EmptyState text={empty} />
            </TableCell>
          </TableRow>
        )}
      </TableBody>
    </Table>
  )
}
