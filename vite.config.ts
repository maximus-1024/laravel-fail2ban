/// <reference types="vitest/config" />
import path from "node:path"
import { fileURLToPath } from "node:url"
import react from "@vitejs/plugin-react"
import tailwindcss from "@tailwindcss/vite"
import { defineConfig } from "vite"

const here = path.dirname(fileURLToPath(import.meta.url))
const panel = path.resolve(here, "resources/panel")

// 产物固定为 dist/app.js 与 dist/app.css：不带哈希、不拆包、不产出 index.html。
// 后端照 Horizon 的做法把这两个文件读出来内联进 Blade 外壳页面，所以 JS 用 iife，
// 既能放进普通 <script>，也能放进 type="module"。
export default defineConfig({
  root: panel,
  publicDir: false,
  // root 指向 resources/panel，把缓存放回仓库根的 node_modules（已被 .gitignore 忽略）
  cacheDir: path.resolve(here, "node_modules/.vite"),
  plugins: [react(), tailwindcss()],
  resolve: { alias: { "@": panel } },
  build: {
    outDir: path.resolve(here, "dist"),
    emptyOutDir: true,
    cssCodeSplit: false,
    modulePreload: false,
    sourcemap: false,
    assetsInlineLimit: Number.MAX_SAFE_INTEGER,
    chunkSizeWarningLimit: 1200,
    rolldownOptions: {
      input: path.resolve(panel, "main.tsx"),
      output: {
        format: "iife",
        codeSplitting: false,
        entryFileNames: "app.js",
        assetFileNames: "app[extname]",
      },
    },
  },
  test: {
    environment: "jsdom",
    setupFiles: [path.resolve(panel, "test/setup.ts")],
    include: ["**/*.test.tsx"],
  },
})
