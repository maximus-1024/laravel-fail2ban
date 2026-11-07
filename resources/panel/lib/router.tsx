import * as React from "react"
import type { Route } from "@/app"

/**
 * 几个固定页面，用不着路由库：history 模式，basename 取 window.Fail2Ban.path。
 * 页面清单只在 app.tsx 的 PAGES 一处；这里返回规范化后的路径，认不认识由 PAGES 决定。
 * 查询参数只用来把搜索词带进页面（全局搜索跳转、刷新后保留）。
 */
function basename(): string {
  return (window.Fail2Ban?.path ?? "/fail2ban").replace(/\/+$/, "")
}

function current(): string {
  const base = basename()
  let path = window.location.pathname
  if (base && path.startsWith(base)) path = path.slice(base.length)
  return "/" + path.replace(/^\/+|\/+$/g, "")
}

function href(to: Route, query?: Record<string, string>): string {
  const search = new URLSearchParams(Object.entries(query ?? {}).filter(([, v]) => v !== "")).toString()
  return basename() + (to === "/" ? "/" : to) + (search ? `?${search}` : "")
}

/** 每次跳转加一：页面以它为 key 重新挂载，带着新的查询参数从头开始。 */
let visit = 0
const listeners = new Set<() => void>()
const notify = () => listeners.forEach((l) => l())
const onPopState = () => {
  visit++
  notify()
}

function subscribe(listener: () => void) {
  if (listeners.size === 0) window.addEventListener("popstate", onPopState)
  listeners.add(listener)
  return () => {
    listeners.delete(listener)
    if (listeners.size === 0) window.removeEventListener("popstate", onPopState)
  }
}

/** 跳到某页；地址没变（例如点当前页的侧栏链接）时什么都不做，页面里未保存的修改不会丢。 */
export function navigate(to: Route, query?: Record<string, string>) {
  window.scrollTo?.(0, 0)
  const next = href(to, query)
  if (next === window.location.pathname + window.location.search) return
  window.history.pushState(null, "", next)
  visit++
  notify()
}

/** 页面内改了搜索词：同步到地址栏（刷新后保留），不算一次跳转。 */
export function replaceQuery(query: Record<string, string>) {
  window.history.replaceState(window.history.state, "", href(current() as Route, query))
}

export function useRoute(): string {
  return React.useSyncExternalStore(subscribe, current, current)
}

export function useVisit(): number {
  return React.useSyncExternalStore(subscribe, () => visit, () => visit)
}

/** 进入页面时地址栏里的查询参数。 */
export function queryParam(name: string): string {
  return new URLSearchParams(window.location.search).get(name) ?? ""
}

export function Link({ to, onClick, ...props }: Omit<React.ComponentProps<"a">, "href"> & { to: Route }) {
  return (
    <a
      {...props}
      href={href(to)}
      onClick={(event) => {
        onClick?.(event)
        if (event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return
        event.preventDefault()
        navigate(to)
      }}
    />
  )
}
