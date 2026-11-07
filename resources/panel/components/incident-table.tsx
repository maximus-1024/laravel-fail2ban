import { createColumnHelper, useTable, type TableOptions } from "@tanstack/react-table"
import { CopyIcon, PanelRightOpenIcon } from "lucide-react"
import * as React from "react"
import { RowActions, features, type Features } from "@/components/data-table"
import { DispositionBadge, RuleText } from "@/components/shared"
import { Button } from "@/components/ui/button"
import { DropdownMenuGroup, DropdownMenuItem } from "@/components/ui/dropdown-menu"
import type { Incident } from "@/lib/api"
import { copyText } from "@/lib/clipboard"
import { formatTime, regionName } from "@/lib/format"

const column = createColumnHelper<Features, Incident>()

/**
 * 攻击事件的列：攻击事件页用完整的一套；安全总览的「最近攻击事件」用精简版（compact），
 * 不显示事件编号与行操作。
 */
export function incidentColumns(onOpen: (id: string) => void, compact = false) {
  return column.columns([
    column.accessor("time", {
      header: "时间",
      meta: { label: "时间" },
      cell: ({ getValue }) => <span className="font-mono">{formatTime(getValue())}</span>,
    }),
    column.accessor("visitor", {
      header: "攻击 IP",
      enableHiding: false,
      cell: ({ row }) => (
        <Button variant="ghost" size="sm" className="-ml-2.5 font-mono" onClick={() => onOpen(row.original.id)}>
          {row.original.visitor}
        </Button>
      ),
    }),
    column.accessor("region", {
      header: "地区",
      meta: { label: "地区" },
      cell: ({ getValue }) => {
        const region = getValue()
        return region ? regionName(region) : "—"
      },
    }),
    ...(compact
      ? []
      : [
          column.accessor("id", {
            header: "事件编号",
            meta: { label: "事件编号" },
            cell: ({ getValue }) => <span className="font-mono">{getValue()}</span>,
          }),
        ]),
    column.accessor((i) => i.rule?.id ?? "manual", {
      id: "rule",
      header: "触发规则",
      filterFn: "arrIncludesSome",
      meta: { label: "触发规则" },
      cell: ({ row }) => <RuleText incident={row.original} />,
    }),
    column.accessor("count", {
      header: "命中次数",
      meta: { label: "命中次数", className: "text-right tabular-nums" },
      cell: ({ getValue }) => {
        const count = getValue()
        return count == null ? "无" : `${count} 次`
      },
    }),
    column.accessor("disposition", {
      header: "处置",
      filterFn: "arrIncludesSome",
      meta: { label: "处置" },
      cell: ({ row }) => <DispositionBadge incident={row.original} />,
    }),
    ...(compact
      ? []
      : [
          column.display({
            id: "actions",
            enableHiding: false,
            cell: ({ row }) => (
              <RowActions label={`${row.original.visitor} 的更多操作`}>
                <DropdownMenuGroup>
                  <DropdownMenuItem onSelect={() => onOpen(row.original.id)}>
                    <PanelRightOpenIcon />
                    查看详情
                  </DropdownMenuItem>
                  <DropdownMenuItem onSelect={() => copyText(row.original.visitor, " IP")}>
                    <CopyIcon />
                    复制 IP
                  </DropdownMenuItem>
                  <DropdownMenuItem onSelect={() => copyText(row.original.id, "事件编号")}>
                    <CopyIcon />
                    复制事件编号
                  </DropdownMenuItem>
                </DropdownMenuGroup>
              </RowActions>
            ),
          }),
        ]),
  ])
}

/** 攻击事件表格的实例；options 里放分页、筛选等由页面管理的状态。 */
export function useIncidentTable({
  data,
  onOpen,
  compact = false,
  options,
}: {
  data: Incident[] | undefined
  onOpen: (id: string) => void
  compact?: boolean
  options?: Partial<TableOptions<Features, Incident>>
}) {
  const columns = React.useMemo(() => incidentColumns(onOpen, compact), [onOpen, compact])
  return useTable({ features, data: data ?? NONE, columns, getRowId: (i) => i.id, ...options })
}

const NONE: Incident[] = []
