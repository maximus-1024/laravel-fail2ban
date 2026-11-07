import { cleanup } from "@testing-library/react"
import { afterEach } from "vitest"
import { resetMock } from "@/lib/mock"

// jsdom 缺的浏览器接口：Sidebar 用 matchMedia，Recharts 与 Radix 用 ResizeObserver 等。
Object.defineProperty(window, "matchMedia", {
  writable: true,
  value: (query: string) => ({
    matches: false,
    media: query,
    onchange: null,
    addEventListener: () => {},
    removeEventListener: () => {},
    addListener: () => {},
    removeListener: () => {},
    dispatchEvent: () => false,
  }),
})

class ResizeObserverStub {
  observe() {}
  unobserve() {}
  disconnect() {}
}
globalThis.ResizeObserver ??= ResizeObserverStub as unknown as typeof ResizeObserver
Element.prototype.scrollIntoView ??= () => {}
Element.prototype.hasPointerCapture ??= () => false
Element.prototype.releasePointerCapture ??= () => {}
window.scrollTo = () => {}

window.Fail2Ban = { path: "/fail2ban", api: "/fail2ban/api", user: "admin" }

afterEach(() => {
  cleanup()
  resetMock()
})
