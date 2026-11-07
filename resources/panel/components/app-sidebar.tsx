import { ShieldCheckIcon } from "lucide-react"
import type { PAGES, Route } from "@/app"
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupContent,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  useSidebar,
} from "@/components/ui/sidebar"
import { Link } from "@/lib/router"

export function AppSidebar({ pages, route, user }: { pages: typeof PAGES; route: Route; user: string }) {
  const { setOpenMobile } = useSidebar()
  return (
    <Sidebar collapsible="icon">
      <SidebarHeader>
        <SidebarMenu>
          <SidebarMenuItem>
            <SidebarMenuButton size="lg" tooltip="访问封禁">
              <ShieldCheckIcon />
              <span className="font-semibold">访问封禁</span>
            </SidebarMenuButton>
          </SidebarMenuItem>
        </SidebarMenu>
      </SidebarHeader>
      <SidebarContent>
        <SidebarGroup>
          <SidebarGroupContent>
            <SidebarMenu>
              {pages.map((item) => (
                <SidebarMenuItem key={item.path}>
                  <SidebarMenuButton asChild isActive={route === item.path} tooltip={item.title}>
                    <Link to={item.path} onClick={() => setOpenMobile(false)}>
                      <item.icon />
                      <span>{item.title}</span>
                    </Link>
                  </SidebarMenuButton>
                </SidebarMenuItem>
              ))}
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>
      </SidebarContent>
      <SidebarFooter>
        <p className="truncate px-2 text-xs text-muted-foreground group-data-[collapsible=icon]:hidden">{user}</p>
      </SidebarFooter>
    </Sidebar>
  )
}
