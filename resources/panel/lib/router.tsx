import * as React from "react"
import type { Route } from "@/app"

/**
 * 几个固定页面，用不着路由库：history 模式，basename 取 window.Fail2Ban.path。
 * 页面清单只在 app.tsx 的 PAGES 一处；这里返回规范化后的路径，认不认识由 PAGES 决定。
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

const listeners = new Set<() => void>()

function subscribe(listener: () => void) {
  listeners.add(listener)
  window.addEventListener("popstate", listener)
  return () => {
    listeners.delete(listener)
    window.removeEventListener("popstate", listener)
  }
}

function navigate(to: Route) {
  window.history.pushState(null, "", basename() + (to === "/" ? "/" : to))
  listeners.forEach((l) => l())
  window.scrollTo?.(0, 0)
}

export function useRoute(): string {
  return React.useSyncExternalStore(subscribe, current, current)
}

export function Link({ to, onClick, ...props }: Omit<React.ComponentProps<"a">, "href"> & { to: Route }) {
  return (
    <a
      {...props}
      href={basename() + (to === "/" ? "/" : to)}
      onClick={(event) => {
        onClick?.(event)
        if (event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return
        event.preventDefault()
        navigate(to)
      }}
    />
  )
}
