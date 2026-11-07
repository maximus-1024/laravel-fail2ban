import "./index.css"
import { StrictMode } from "react"
import { createRoot } from "react-dom/client"
import { App } from "./app"

// 深色模式跟随系统：照官方 Vite 深色模式的做法在根元素上切换 .dark，系统设置变化时同步。
const scheme = window.matchMedia("(prefers-color-scheme: dark)")
const applyScheme = () => document.documentElement.classList.toggle("dark", scheme.matches)
applyScheme()
scheme.addEventListener("change", applyScheme)

const root = document.getElementById("app")
if (root) {
  createRoot(root).render(
    <StrictMode>
      <App />
    </StrictMode>,
  )
}
