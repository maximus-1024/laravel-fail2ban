import { BanIcon, SearchIcon, TriangleAlertIcon } from "lucide-react"
import * as React from "react"
import type { PAGES } from "@/app"
import { Button } from "@/components/ui/button"
import { Command, CommandDialog, CommandEmpty, CommandGroup, CommandInput, CommandItem, CommandList, CommandSeparator } from "@/components/ui/command"
import { Kbd, KbdGroup } from "@/components/ui/kbd"
import { navigate } from "@/lib/router"

/** 像 IP、网段或事件编号的输入才给「在…中搜索」两项；接口按包含匹配，输入一部分也能搜到。 */
export function looksSearchable(text: string): boolean {
  const q = text.trim()
  return /^ban-/i.test(q) || (/\d/.test(q) && /^[0-9a-f.:/]+$/i.test(q) && /[.:]/.test(q))
}

const isMac = () => /Mac|iPhone|iPad/.test(navigator.platform || navigator.userAgent)

/**
 * 全局搜索：照 shadcn-admin 的 Search 按钮与 CommandMenu，用 CommandDialog 实现。
 * 可以跳到任一页面；输入 IP 或事件编号时，可直接到攻击事件或封禁列表里按它搜索。
 */
export function CommandMenu({ pages }: { pages: typeof PAGES }) {
  const [open, setOpen] = React.useState(false)
  const [query, setQuery] = React.useState("")
  const q = query.trim()

  React.useEffect(() => {
    const down = (e: KeyboardEvent) => {
      if (e.key.toLowerCase() === "k" && (e.metaKey || e.ctrlKey)) {
        e.preventDefault()
        setOpen((o) => !o)
      }
    }
    document.addEventListener("keydown", down)
    return () => document.removeEventListener("keydown", down)
  }, [])

  const run = (go: () => void) => {
    setOpen(false)
    setQuery("")
    go()
  }

  return (
    <>
      <Button variant="outline" size="icon-sm" className="sm:hidden" aria-label="搜索" onClick={() => setOpen(true)}>
        <SearchIcon />
      </Button>
      <Button variant="outline" size="sm" className="hidden sm:inline-flex" aria-keyshortcuts="Control+K Meta+K" onClick={() => setOpen(true)}>
        <SearchIcon data-icon="inline-start" />
        搜索
        <KbdGroup>
          <Kbd>{isMac() ? "⌘" : "Ctrl"}</Kbd>
          <Kbd>K</Kbd>
        </KbdGroup>
      </Button>
      <CommandDialog
        open={open}
        onOpenChange={(o) => {
          setOpen(o)
          if (!o) setQuery("")
        }}
        title="全局搜索"
        description="跳转到某个页面，或输入 IP、事件编号搜索"
      >
        <Command>
          <CommandInput placeholder="跳转页面，或输入 IP、事件编号搜索…" value={query} onValueChange={setQuery} />
          <CommandList>
            {/* 「在…中搜索」两项总会显示（forceMount），这时不需要空态 */}
            {!looksSearchable(q) && <CommandEmpty>没有匹配的页面。输入 IP 或事件编号可以直接搜索。</CommandEmpty>}
            {looksSearchable(q) && (
              <>
                <CommandGroup heading="搜索" forceMount>
                  <CommandItem forceMount value={`search-incidents ${q}`} onSelect={() => run(() => navigate("/incidents", { q }))}>
                    <TriangleAlertIcon />
                    在攻击事件中搜索「{q}」
                  </CommandItem>
                  <CommandItem forceMount value={`search-bans ${q}`} onSelect={() => run(() => navigate("/bans", { q }))}>
                    <BanIcon />
                    在封禁列表中搜索「{q}」
                  </CommandItem>
                </CommandGroup>
                <CommandSeparator />
              </>
            )}
            <CommandGroup heading="页面">
              {pages.map((p) => (
                <CommandItem key={p.path} value={p.title} onSelect={() => run(() => navigate(p.path))}>
                  <p.icon />
                  {p.title}
                </CommandItem>
              ))}
            </CommandGroup>
          </CommandList>
        </Command>
      </CommandDialog>
    </>
  )
}
