import { createColumnHelper, useTable } from "@tanstack/react-table"
import { PlusIcon } from "lucide-react"
import * as React from "react"
import { AllowDialog } from "@/components/allow-dialog"
import { ConfirmButton } from "@/components/confirm-button"
import { DataTable, features, type Features } from "@/components/data-table"
import { PageHeader } from "@/components/page-header"
import { LoadError } from "@/components/shared"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { api, type AllowEntry } from "@/lib/api"
import { formatTime } from "@/lib/format"
import { useApi } from "@/lib/use-api"

type Builtin = { entry: string; label: string }
const custom = createColumnHelper<Features, AllowEntry>()
const builtin = createColumnHelper<Features, Builtin>()
const NO_CUSTOM: AllowEntry[] = []
const NO_BUILTIN: Builtin[] = []

const builtinColumns = builtin.columns([
  builtin.accessor("entry", { header: "IP 或网段", cell: ({ getValue }) => <span className="font-mono">{getValue()}</span> }),
  builtin.accessor("label", { header: "来源" }),
])

function customColumns(onChanged: () => void) {
  return custom.columns([
    custom.accessor("entry", { header: "IP 或网段", cell: ({ getValue }) => <span className="font-mono">{getValue()}</span> }),
    custom.accessor("note", { header: "备注", meta: { className: "max-w-72 min-w-32 whitespace-normal" }, cell: ({ getValue }) => getValue() || "—" }),
    custom.accessor("added_by", { header: "添加人" }),
    custom.accessor("added_at", { header: "添加时间", cell: ({ getValue }) => <span className="font-mono">{formatTime(getValue())}</span> }),
    custom.display({
      id: "actions",
      header: () => <span className="sr-only">操作</span>,
      meta: { className: "text-right" },
      cell: ({ row: { original: e } }) => (
        <ConfirmButton
          label="移除"
          title={`把 ${e.entry} 移出白名单？`}
          description="移除后这个地址会重新参与统计，达到规则的出现次数就会被封。"
          confirm="确认移除"
          success={`已把 ${e.entry} 移出白名单`}
          run={() => api.disallow(e.entry)}
          onDone={onChanged}
        />
      ),
    }),
  ])
}

export function AllowlistPage() {
  const { data, error, loading, reload } = useApi(() => api.allowlist(), [])
  const columns = React.useMemo(() => customColumns(reload), [reload])
  const customTable = useTable({ features, data: data?.data ?? NO_CUSTOM, columns, getRowId: (e) => e.entry, manualPagination: true })
  const builtinTable = useTable({ features, data: data?.builtin ?? NO_BUILTIN, columns: builtinColumns, getRowId: (e) => e.entry, manualPagination: true })

  return (
    <>
      <PageHeader
        title="白名单"
        description="白名单里的 IP 和网段不统计命中，也不会被封。把一个 IP 加进来，会同时解除它当前的封禁。"
        actions={
          <AllowDialog
            onDone={reload}
            trigger={
              <Button>
                <PlusIcon data-icon="inline-start" />
                添加
              </Button>
            }
          />
        }
      />
      {error ? <LoadError error={error} onRetry={reload} /> : null}

      <Card>
        <CardHeader>
          <CardTitle>自定义条目</CardTitle>
          <CardDescription>在面板里添加的条目</CardDescription>
        </CardHeader>
        <CardContent>
          <DataTable table={customTable} loading={loading && !data} skeletonRows={3} empty="还没有自定义条目" />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>内置条目，只读</CardTitle>
          <CardDescription>内网与回环地址、Cloudflare 地址段、服务器配置里的条目。取到内网或 Cloudflare 地址说明拿到的不是真实访客，会记一条警告。</CardDescription>
        </CardHeader>
        <CardContent>
          <DataTable table={builtinTable} loading={loading && !data} skeletonRows={3} empty="当前没有" />
        </CardContent>
      </Card>
    </>
  )
}
