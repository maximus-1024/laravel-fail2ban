import { AllowDialog } from "@/components/allow-dialog"
import { ConfirmButton } from "@/components/confirm-button"
import { EmptyRow, LoadError, LoadingRows } from "@/components/shared"
import { Button } from "@/components/ui/button"
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { api } from "@/lib/api"
import { formatTime } from "@/lib/format"
import { useApi } from "@/lib/use-api"

export function AllowlistPage() {
  const { data, error, loading, reload } = useApi(() => api.allowlist(), [])

  return (
    <>
      <p className="text-sm text-muted-foreground">白名单里的 IP 和网段不统计命中，也不会被封。把一个 IP 加进来，会同时解除它当前的封禁。</p>
      {error ? <LoadError error={error} onRetry={reload} /> : null}

      <Card>
        <CardHeader>
          <CardTitle>自定义条目</CardTitle>
          <CardDescription>在面板里添加的条目</CardDescription>
          <CardAction>
            <AllowDialog onDone={reload} trigger={<Button>添加</Button>} />
          </CardAction>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>IP 或网段</TableHead>
                <TableHead>备注</TableHead>
                <TableHead>添加人</TableHead>
                <TableHead>添加时间</TableHead>
                <TableHead>操作</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {loading && !data ? (
                <LoadingRows cols={5} rows={3} />
              ) : !data || data.data.length === 0 ? (
                <EmptyRow cols={5} text="还没有自定义条目" />
              ) : (
                data.data.map((e) => (
                  <TableRow key={e.entry}>
                    <TableCell className="font-mono">{e.entry}</TableCell>
                    <TableCell className="max-w-72 whitespace-normal">{e.note || "—"}</TableCell>
                    <TableCell>{e.added_by}</TableCell>
                    <TableCell>{formatTime(e.added_at)}</TableCell>
                    <TableCell>
                      <ConfirmButton
                        label="移除"
                        title={`把 ${e.entry} 移出白名单？`}
                        description="移除后这个地址会重新参与统计，达到规则的出现次数就会被封。"
                        confirm="确认移除"
                        success={`已把 ${e.entry} 移出白名单`}
                        run={() => api.disallow(e.entry)}
                        onDone={reload}
                      />
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>内置条目，只读</CardTitle>
          <CardDescription>内网与回环地址、Cloudflare 地址段、服务器配置里的条目。取到内网或 Cloudflare 地址说明拿到的不是真实访客，会记一条警告。</CardDescription>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>IP 或网段</TableHead>
                <TableHead>来源</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {loading && !data ? (
                <LoadingRows cols={2} rows={3} />
              ) : !data || data.builtin.length === 0 ? (
                <EmptyRow cols={2} text="当前没有" />
              ) : (
                data.builtin.map((e) => (
                  <TableRow key={e.entry}>
                    <TableCell className="font-mono">{e.entry}</TableCell>
                    <TableCell>{e.label}</TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </>
  )
}
