import * as React from "react"

interface ApiState<T> {
  data: T | undefined
  error: unknown
  loading: boolean
  reload: () => void
  /** 用改动接口返回的新值直接替换，省掉一次重新读取。 */
  update: (data: T) => void
}

/** 读取接口；deps 变化时重新加载，旧请求的结果丢弃。 */
export function useApi<T>(load: () => Promise<T>, deps: React.DependencyList): ApiState<T> {
  const [state, setState] = React.useState<{ data?: T; error?: unknown; loading: boolean }>({ loading: true })
  const [tick, setTick] = React.useState(0)

  React.useEffect(() => {
    let alive = true
    setState((s) => ({ ...s, loading: true, error: undefined }))
    load().then(
      (data) => alive && setState({ data, loading: false }),
      (error) => alive && setState((s) => ({ data: s.data, error, loading: false })),
    )
    return () => {
      alive = false
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, tick])

  const reload = React.useCallback(() => setTick((t) => t + 1), [])
  const update = React.useCallback((data: T) => setState({ data, loading: false }), [])
  return { data: state.data, error: state.error, loading: state.loading, reload, update }
}
