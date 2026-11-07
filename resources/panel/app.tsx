import { BanIcon, FileClockIcon, LayoutDashboardIcon, ListChecksIcon, SettingsIcon, TriangleAlertIcon } from "lucide-react"
import { AppSidebar } from "@/components/app-sidebar"
import { StatusProvider, useStatus } from "@/components/status"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Breadcrumb, BreadcrumbItem, BreadcrumbLink, BreadcrumbList, BreadcrumbPage, BreadcrumbSeparator } from "@/components/ui/breadcrumb"
import { Separator } from "@/components/ui/separator"
import { SidebarInset, SidebarProvider, SidebarTrigger } from "@/components/ui/sidebar"
import { Toaster } from "@/components/ui/sonner"
import { TooltipProvider } from "@/components/ui/tooltip"
import { MODES } from "@/lib/format"
import { Link, useRoute } from "@/lib/router"
import { AllowlistPage } from "@/pages/allowlist"
import { AuditPage } from "@/pages/audit"
import { BansPage } from "@/pages/bans"
import { IncidentsPage } from "@/pages/incidents"
import { OverviewPage } from "@/pages/overview"
import { SettingsPage } from "@/pages/settings"

/** 页面清单：路由、侧栏与标题都取这一份；认不出的地址显示第一页。 */
export const PAGES = [
  { path: "/", title: "安全总览", icon: LayoutDashboardIcon, Page: OverviewPage },
  { path: "/incidents", title: "攻击事件", icon: TriangleAlertIcon, Page: IncidentsPage },
  { path: "/bans", title: "封禁列表", icon: BanIcon, Page: BansPage },
  { path: "/allowlist", title: "白名单", icon: ListChecksIcon, Page: AllowlistPage },
  { path: "/settings", title: "防护配置", icon: SettingsIcon, Page: SettingsPage },
  { path: "/audit", title: "操作日志", icon: FileClockIcon, Page: AuditPage },
] as const
export type Route = (typeof PAGES)[number]["path"]

function Shell() {
  const path = useRoute()
  const { settings } = useStatus()
  const { path: route, title, Page } = PAGES.find((p) => p.path === path) ?? PAGES[0]

  return (
    <SidebarProvider>
      <AppSidebar pages={PAGES} route={route} user={window.Fail2Ban?.user ?? ""} />
      <SidebarInset>
        <header className="flex h-16 shrink-0 items-center gap-2 px-4">
          <SidebarTrigger className="-ml-1" />
          <Separator orientation="vertical" className="mr-2 data-vertical:h-4 data-vertical:self-auto" />
          <Breadcrumb>
            <BreadcrumbList>
              <BreadcrumbItem className="hidden md:block">
                <BreadcrumbLink asChild>
                  <Link to="/">访问封禁</Link>
                </BreadcrumbLink>
              </BreadcrumbItem>
              <BreadcrumbSeparator className="hidden md:block" />
              <BreadcrumbItem>
                <BreadcrumbPage>{title}</BreadcrumbPage>
              </BreadcrumbItem>
            </BreadcrumbList>
          </Breadcrumb>
          {settings && (
            <Badge variant={settings.mode === "block" ? "default" : "secondary"} className="ml-auto">
              {MODES[settings.mode]}
            </Badge>
          )}
        </header>
        <div className="flex flex-1 flex-col gap-4 p-4 pt-0">
          {settings?.enabled === false && (
            <Alert variant="destructive">
              <AlertTitle>总开关已关闭</AlertTitle>
              <AlertDescription>服务器配置里的总开关是关闭的，中间件不做任何检测与拦截。面板里的设置会保存，但在打开总开关之前不会生效。</AlertDescription>
            </Alert>
          )}
          <Page />
        </div>
      </SidebarInset>
    </SidebarProvider>
  )
}

export function App() {
  return (
    <TooltipProvider>
      <StatusProvider>
        <Shell />
      </StatusProvider>
      <Toaster position="top-center" theme="system" />
    </TooltipProvider>
  )
}
