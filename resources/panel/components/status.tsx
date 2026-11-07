import * as React from "react"
import { api, type Settings } from "@/lib/api"
import { useApi } from "@/lib/use-api"

interface Status {
  /** 设置接口的返回：顶部状态、筛选下拉的规则清单与防护配置页都用这一份。 */
  settings: Settings | undefined
  error: unknown
  reload: () => void
  /** 重新取一次；上一次请求发出不到 FRESH_MS 时跳过（例如刚打开面板，全局那次请求还没回来）。 */
  refresh: () => void
  /** 保存设置后用接口返回的新值替换，不再多请求一次。 */
  update: (settings: Settings) => void
}

/** 几毫秒内取过就算新鲜，不再重取。 */
export const FRESH_MS = 5_000

const StatusContext = React.createContext<Status>({ settings: undefined, error: undefined, reload: () => {}, refresh: () => {}, update: () => {} })

export function StatusProvider({ children }: { children: React.ReactNode }) {
  // 上一次请求发出的时间；undefined 表示首次请求还没发出（子组件的 effect 先于这里运行），它马上就发
  const requestedAt = React.useRef<number>(undefined)
  const load = React.useCallback(() => {
    requestedAt.current = Date.now()
    return api.settings()
  }, [])
  const { data, error, reload, update } = useApi(load, [])
  const refresh = React.useCallback(() => {
    if (requestedAt.current === undefined || Date.now() - requestedAt.current < FRESH_MS) return
    reload()
  }, [reload])
  const value = React.useMemo(() => ({ settings: data, error, reload, refresh, update }), [data, error, reload, refresh, update])
  return <StatusContext.Provider value={value}>{children}</StatusContext.Provider>
}

export function useStatus() {
  return React.useContext(StatusContext)
}
