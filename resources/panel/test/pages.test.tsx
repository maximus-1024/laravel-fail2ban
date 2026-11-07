import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react"
import { useTable } from "@tanstack/react-table"
import * as React from "react"
import { afterEach, describe, expect, it, vi } from "vitest"
import { App } from "@/app"
import { ConfirmButton } from "@/components/confirm-button"
import { DataTable, DataTableFacetedFilter, features } from "@/components/data-table"
import { useIncidentTable } from "@/components/incident-table"
import { FRESH_MS } from "@/components/status"
import { api, requestUrl, type Incident, type IncidentDetail, type Settings } from "@/lib/api"
import { countUnit, offenseMinutes, regionName } from "@/lib/format"
import { mockRequest } from "@/lib/mock"

afterEach(() => {
  vi.restoreAllMocks()
})

function open(path: string) {
  window.history.pushState(null, "", `/fail2ban${path}`)
  return render(<App />)
}

/** 防护配置页左侧分组导航里的按钮。 */
const navItem = (name: string) => within(screen.getByRole("navigation", { name: "配置分组" })).getByRole("button", { name: new RegExp(name) })

/** 防护配置页切换分组。 */
async function section(name: string) {
  await screen.findByRole("navigation", { name: "配置分组" })
  fireEvent.click(navItem(name))
  await waitFor(() => expect(navItem(name).getAttribute("aria-current")).toBe("true"))
}

/** 打开工具栏里的筛选弹层并选一项。 */
async function pick(filter: string, option: string) {
  fireEvent.click(screen.getByRole("button", { name: new RegExp(`^${filter}`) }))
  fireEvent.click(await screen.findByRole("option", { name: option }))
}

describe("面板页面（开发假数据）", () => {
  it("安全总览：指标、排行与最近事件", async () => {
    open("/")
    expect(await screen.findByText("1,341")).toBeTruthy()
    expect(screen.getByText("命中规则分布")).toBeTruthy()
    expect(screen.getByText("攻击源 IP 排行")).toBeTruthy()
    expect(screen.getByText("/.env")).toBeTruthy()
    expect(screen.getByText("最近攻击事件")).toBeTruthy()
    expect((await screen.findAllByText("拦截模式")).length).toBeGreaterThan(0)
    // 来源地区：接口给国家代码，界面显示中文国名
    const regions = screen.getByText("来源地区排行").closest("[data-slot=card]") as HTMLElement
    expect(within(regions).getByText("美国")).toBeTruthy()
    expect(within(regions).queryByText("US")).toBeNull()
  })

  it("攻击事件：列表与右侧详情，访客可控字符串按文字渲染", async () => {
    open("/incidents")
    const ip = await screen.findByRole("button", { name: "198.51.100.23" })
    expect(screen.getByText("BAN-20261106-7K2M9Q")).toBeTruthy()
    fireEvent.click(ip)
    const sheet = await screen.findByRole("dialog")
    expect(within(sheet).getByText("事件详情")).toBeTruthy()
    expect(await within(sheet).findByText("攻击者信息")).toBeTruthy()
    // 假数据里的请求地址带 <script>，必须原样作为文字出现，不能变成元素
    expect(within(sheet).getByText(/<script>alert\(1\)<\/script>/)).toBeTruthy()
    expect(document.querySelector("script")).toBeNull()
  })

  it("封禁列表：累犯标记、剩余时间、手动封禁与解封二次确认", async () => {
    open("/bans")
    expect(await screen.findByText("共 5 个访客正在被封禁")).toBeTruthy()
    expect(screen.getByText("累犯第 2 次，时长已加长")).toBeTruthy()
    expect(screen.getByText("IPv6 按 64 位网段封禁")).toBeTruthy()
    expect(within(screen.getByText("203.0.113.47").closest("tr")!).getByText("荷兰")).toBeTruthy()
    expect(screen.getByRole("button", { name: "手动封禁" })).toBeTruthy()
    fireEvent.click(screen.getAllByRole("button", { name: "解封" })[0])
    expect(await screen.findByRole("alertdialog")).toBeTruthy()
    expect(screen.getByText("解封 203.0.113.47？")).toBeTruthy()
  })

  it("手动封禁：422 字段错误显示在对应字段", async () => {
    open("/bans")
    fireEvent.click(await screen.findByRole("button", { name: "手动封禁" }))
    const dialog = await screen.findByRole("dialog")
    fireEvent.change(within(dialog).getByLabelText("IP 地址"), { target: { value: "not-an-ip" } })
    fireEvent.click(within(dialog).getByRole("button", { name: "确认封禁" }))
    expect(await within(dialog).findByText("请输入一个合法的 IP 地址")).toBeTruthy()
    expect(within(dialog).getByText("请填写备注")).toBeTruthy()
  })

  it("白名单：自定义条目与内置只读条目", async () => {
    open("/allowlist")
    expect(await screen.findByText("办公室出口")).toBeTruthy()
    expect(screen.getByText("内置条目，只读")).toBeTruthy()
    expect(screen.getByText("10.0.0.0/8")).toBeTruthy()
    expect(screen.getAllByRole("button", { name: "移除" }).length).toBe(3)
    // note 为 null 的条目显示占位
    const row = screen.getByText("192.0.2.5").closest("tr")!
    expect(within(row).getByText("—")).toBeTruthy()
  })

  it("防护配置：规则按接口返回几条画几条、累犯加长例子、编辑抽屉的白话总结随输入变化", async () => {
    open("/settings")
    await section("防护规则")
    for (const name of ["404 扫描", "敏感文件探测", "扫描器特征", "攻击特征", "已知漏洞探测", "登录爆破"]) expect(screen.getByText(name)).toBeTruthy()
    expect(screen.getAllByRole("button", { name: "编辑" }).length).toBe(6)
    await section("累犯加长")
    expect(screen.getByText(/以404 扫描为例：第 1 次封 30 分钟，第 2 次封 1 小时/)).toBeTruthy()
    // 取值范围来自接口的 limits
    expect(screen.getByText(/每多被封一次，时长乘以这个数。可填 2 到 10。/)).toBeTruthy()
    await section("防护规则")
    fireEvent.click(screen.getAllByRole("button", { name: "编辑" })[1])
    const sheet = await screen.findByRole("dialog")
    expect(within(sheet).getByText("编辑规则 · 敏感文件探测")).toBeTruthy()
    const summary = within(sheet).getByTestId("rule-summary")
    expect(summary.textContent).toContain("10 分钟内请求了 3 个不同的地址，封禁 2 小时")
    fireEvent.change(within(sheet).getByLabelText("出现次数"), { target: { value: "5" } })
    expect(summary.textContent).toContain("请求了 5 个不同的地址")
    // 累犯加长：第 2 次 = 2 小时 × 2
    expect(summary.textContent).toContain("第 2 次被封 4 小时")
  })

  it("防护配置：只请求一次设置；保存规则不丢未保存的修改，保存后顶部状态随之更新", async () => {
    const load = vi.spyOn(api, "settings")
    open("/settings")
    fireEvent.click(await screen.findByRole("radio", { name: "观察模式" }))
    expect(load).toHaveBeenCalledTimes(1)
    const save = screen.getByRole("button", { name: "保存修改" }) as HTMLButtonElement
    expect(save.disabled).toBe(false)

    await section("防护规则")
    fireEvent.click(screen.getAllByRole("button", { name: "编辑" })[0])
    const sheet = await screen.findByRole("dialog")
    fireEvent.change(within(sheet).getByLabelText("封禁时长，单位分钟"), { target: { value: "45" } })
    fireEvent.click(within(sheet).getByRole("button", { name: "确定" }))
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull())
    expect(screen.getByText("45 分钟")).toBeTruthy()
    expect(save.disabled).toBe(false)
    await section("运行模式")
    expect(screen.getByRole("radio", { name: "观察模式" }).getAttribute("aria-checked")).toBe("true")

    fireEvent.click(save)
    await waitFor(() => expect(save.disabled).toBe(true))
    expect(within(screen.getByRole("banner")).getByText("观察模式")).toBeTruthy()
    expect(load).toHaveBeenCalledTimes(1)
  })

  it("提示文字：长度上限取自接口，超长时 422 显示在字段下", async () => {
    const base = (await mockRequest("GET", "/settings")).data as Settings
    vi.spyOn(api, "settings").mockResolvedValue({ ...base, limits: { ...base.limits, message: [1, 20] } })
    open("/settings")
    await section("拦截响应")
    const message = screen.getByLabelText("给访客的提示文字") as HTMLTextAreaElement
    expect(message.maxLength).toBe(20)
    expect(screen.getByText("最多 20 个字。")).toBeTruthy()

    // 浏览器会挡住超长输入；这里绕过它，确认后端 422 的 response.message 显示在字段下
    fireEvent.change(message, { target: { value: "字".repeat(501) } })
    fireEvent.click(screen.getByRole("button", { name: "保存修改" }))
    const field = message.closest("[data-slot=field]") as HTMLElement
    expect(await within(field).findByText("最多 500 个字")).toBeTruthy()
    expect(message.getAttribute("aria-invalid")).toBe("true")
  })

  it("提示文字：接口没给 limits.message 时不限制长度", async () => {
    const base = (await mockRequest("GET", "/settings")).data as Settings
    const { message: _omit, ...limits } = base.limits
    vi.spyOn(api, "settings").mockResolvedValue({ ...base, limits })
    open("/settings")
    await section("拦截响应")
    const message = screen.getByLabelText("给访客的提示文字")
    expect(message.hasAttribute("maxlength")).toBe(false)
    expect(screen.queryByText(/^最多 \d+ 个字。$/)).toBeNull()
  })

  it("防护配置：从别的页面进入会重取一次设置，刚取过就不重取", async () => {
    const t0 = Date.now()
    const clock = vi.spyOn(Date, "now").mockReturnValue(t0)
    const load = vi.spyOn(api, "settings")
    open("/")
    expect(await screen.findByText("1,341")).toBeTruthy()
    expect(load).toHaveBeenCalledTimes(1)

    // 刚取过：进入防护配置页不重取
    fireEvent.click(screen.getByRole("link", { name: "防护配置" }))
    expect(await screen.findByText("防护规则")).toBeTruthy()
    expect(load).toHaveBeenCalledTimes(1)

    // 过了新鲜期：离开再进入，重取一次
    fireEvent.click(screen.getByRole("link", { name: "安全总览" }))
    expect(await screen.findByText("1,341")).toBeTruthy()
    clock.mockReturnValue(t0 + FRESH_MS)
    fireEvent.click(screen.getByRole("link", { name: "防护配置" }))
    expect(await screen.findByText("防护规则")).toBeTruthy()
    await waitFor(() => expect(load).toHaveBeenCalledTimes(2))
  })

  it("防护配置：重取回来的数据更新命中数，但不冲掉未保存的修改", async () => {
    const base = (await mockRequest("GET", "/settings")).data as Settings
    const t0 = Date.now()
    const clock = vi.spyOn(Date, "now").mockReturnValue(t0)
    let resolve: (s: Settings) => void = () => {}
    const load = vi
      .spyOn(api, "settings")
      .mockResolvedValueOnce(base)
      .mockImplementationOnce(() => new Promise<Settings>((r) => (resolve = r)))
    open("/")
    expect(await screen.findByText("1,341")).toBeTruthy()
    clock.mockReturnValue(t0 + FRESH_MS)
    fireEvent.click(screen.getByRole("link", { name: "防护配置" }))
    expect(await screen.findByText("防护规则")).toBeTruthy()
    await waitFor(() => expect(load).toHaveBeenCalledTimes(2))

    // 重取还没回来时改了运行模式、累犯倍数与提示文字
    fireEvent.click(screen.getByRole("radio", { name: "观察模式" }))
    await section("累犯加长")
    fireEvent.change(screen.getByLabelText("加长倍数"), { target: { value: "3" } })
    await section("拦截响应")
    fireEvent.change(screen.getByLabelText("给访客的提示文字"), { target: { value: "草稿" } })

    // 别人从命令行改了模式与倍数，命中数也变了
    resolve({ ...base, mode: "off", repeat: { ...base.repeat, factor: 5 }, rules: base.rules.map((r, i) => (i === 0 ? { ...r, hits_24h: 9999 } : r)) })
    await section("防护规则")
    expect(await screen.findByText("9,999")).toBeTruthy()
    await section("运行模式")
    expect(screen.getByText("乘以 5")).toBeTruthy()
    expect(screen.getByRole("radio", { name: "观察模式" }).getAttribute("aria-checked")).toBe("true")
    await section("累犯加长")
    expect((screen.getByLabelText("加长倍数") as HTMLInputElement).value).toBe("3")
    await section("拦截响应")
    expect((screen.getByLabelText("给访客的提示文字") as HTMLTextAreaElement).value).toBe("草稿")
    expect((screen.getByRole("button", { name: "保存修改" }) as HTMLButtonElement).disabled).toBe(false)
  })

  it("操作日志：表格与筛选", async () => {
    open("/audit")
    expect(await screen.findByText("封 24 小时。备注：反复用错误签名请求代付接口")).toBeTruthy()
    expect(screen.getByText("由「观察」改为「拦截」")).toBeTruthy()
    // 「操作类型」筛选是官方 faceted filter 写法的按钮（Popover + Command）
    expect(screen.getByRole("button", { name: "操作类型" })).toBeTruthy()
  })

  it("操作日志：入口列与保留条数", async () => {
    open("/audit")
    expect(await screen.findByText("入口")).toBeTruthy()
    const consoleRow = screen.getByText("提前解除，当时还剩 12 分钟").closest("tr")!
    expect(within(consoleRow).getByText("命令行")).toBeTruthy()
    const panelRow = screen.getByText("由「观察」改为「拦截」").closest("tr")!
    expect(within(panelRow).getByText("面板")).toBeTruthy()
    expect(screen.getByText("共 5 条，只保留最近 500 条")).toBeTruthy()
  })

  it("攻击事件：保留条数，规则筛选来自接口（含自定义规则）", async () => {
    open("/incidents")
    expect(await screen.findByText("共 10 条，只保留最近 500 条")).toBeTruthy()
    fireEvent.click(screen.getByRole("button", { name: "触发规则" }))
    const listbox = await screen.findByRole("listbox")
    expect(within(listbox).getByText("登录爆破")).toBeTruthy()
    // 6 条规则 + 手动封禁；「全部」改由「清除筛选」表达，不再是一个选项
    expect(within(listbox).getAllByRole("option").length).toBe(7)
  })

  it("事件详情：显示接口的 reason 与中文国名；请求的 method/path 为 null 不出错", async () => {
    open("/incidents")
    fireEvent.click(await screen.findByRole("button", { name: "203.0.113.47" }))
    const sheet = await screen.findByRole("dialog")
    expect(await within(sheet).findByText(/敏感文件探测，10 分钟内 3 个不同地址/)).toBeTruthy()
    expect(within(sheet).getByText("荷兰")).toBeTruthy()
    fireEvent.keyDown(sheet, { key: "Escape" })
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull())

    fireEvent.click(screen.getByRole("button", { name: "198.51.100.90" }))
    const other = await screen.findByRole("dialog")
    expect(await within(other).findByText(/登录爆破，5 分钟内 8 次/)).toBeTruthy()
    // method 与 path 为 null 的那条请求只显示时间与占位
    expect(within(other).getByText(/^\d{2}:\d{2}:\d{2} —$/)).toBeTruthy()
  })

  it("事件详情：reason 为空显示占位；后端过渡期多给 requests[].note 不出错也不显示", async () => {
    const base = (await mockRequest("GET", "/incidents/BAN-20261106-0P5L2K")).data as IncidentDetail
    vi.spyOn(api, "incident").mockResolvedValue({
      ...base,
      reason: null,
      requests: [{ time: base.time, method: "GET", path: "/x", note: "旧字段" } as IncidentDetail["requests"][number]],
    })
    open("/incidents")
    fireEvent.click(await screen.findByRole("button", { name: "198.51.100.90" }))
    const sheet = await screen.findByRole("dialog")
    expect(await within(sheet).findByText("登录爆破，—")).toBeTruthy()
    expect(within(sheet).getByText(/GET \/x/)).toBeTruthy()
    expect(within(sheet).queryByText("旧字段")).toBeNull()
  })

  it("事件详情：手动封禁的 offense 为 null", async () => {
    open("/incidents")
    fireEvent.click(await screen.findByRole("button", { name: "192.0.2.118" }))
    const sheet = await screen.findByRole("dialog")
    expect(await within(sheet).findByText("攻击者信息")).toBeTruthy()
    expect(within(sheet).queryByText(/次被封/)).toBeNull()
  })

  it("封禁列表：解封走查询参数，行消失，事件变成已解封", async () => {
    open("/bans")
    fireEvent.click((await screen.findAllByRole("button", { name: "解封" }))[2])
    expect(await screen.findByText("解封 2001:db8:4c2:91::/64？")).toBeTruthy()
    fireEvent.click(screen.getByRole("button", { name: "确认解封" }))
    expect(await screen.findByText("共 4 个访客正在被封禁")).toBeTruthy()
    expect(screen.queryByText("2001:db8:4c2:91::/64")).toBeNull()
    const res = await mockRequest("GET", "/incidents", { q: "2001:db8" })
    expect((res.data as { data: { disposition: string }[] }).data[0].disposition).toBe("unbanned")
  })

  it("白名单：删除走查询参数，带斜杠的网段也能删", async () => {
    open("/allowlist")
    const row = (await screen.findByText("198.51.100.0/28")).closest("tr")!
    fireEvent.click(within(row).getByRole("button", { name: "移除" }))
    fireEvent.click(await screen.findByRole("button", { name: "确认移除" }))
    await waitFor(() => expect(screen.queryByText("198.51.100.0/28")).toBeNull())
    expect(screen.getAllByRole("button", { name: "移除" }).length).toBe(2)
  })
})

describe("接口与格式", () => {
  it("删除请求把访客键与网段放进查询参数并 URL 编码", () => {
    expect(requestUrl("/bans", { visitor: "2001:db8:4c2:91::/64" })).toBe("/fail2ban/api/bans?visitor=2001%3Adb8%3A4c2%3A91%3A%3A%2F64")
    expect(requestUrl("/allowlist", { entry: "198.51.100.0/28" })).toBe("/fail2ban/api/allowlist?entry=198.51.100.0%2F28")
  })

  it("量词按 count_mode", () => {
    expect(countUnit("distinct")).toBe("个不同地址")
    expect(countUnit("each")).toBe("次")
  })

  it("国家代码转中文国名，转不了原样显示", () => {
    expect(regionName("NL")).toBe("荷兰")
    expect(regionName("US")).toBe("美国")
    expect(regionName("XX")).toBe("XX")
    expect(regionName("T1")).toBe("T1")
  })

  it("累犯加长的时长与后端 BanDuration 一致", () => {
    const repeat = { enabled: true, factor: 2, max_days: 1 }
    expect([1, 2, 3, 4, 5, 6].map((n) => offenseMinutes(240, n, repeat))).toEqual([240, 480, 960, 1440, 1440, 1440])
    // 规则的时长本身比封顶长：按规则的时长
    expect(offenseMinutes(2880, 3, repeat)).toBe(2880)
    expect(offenseMinutes(240, 3, { ...repeat, enabled: false })).toBe(240)
  })
})

describe("合并出来的通用组件", () => {
  it("ConfirmButton：确认后执行、关闭并回调；取消不执行", async () => {
    const run = vi.fn().mockResolvedValue(null)
    const onDone = vi.fn()
    render(<ConfirmButton label="移除" title="确定吗？" description="说明" confirm="确认移除" success="好了" run={run} onDone={onDone} />)
    fireEvent.click(screen.getByRole("button", { name: "移除" }))
    fireEvent.click(await screen.findByRole("button", { name: "取消" }))
    await waitFor(() => expect(screen.queryByRole("alertdialog")).toBeNull())
    expect(run).not.toHaveBeenCalled()

    fireEvent.click(screen.getByRole("button", { name: "移除" }))
    expect(await screen.findByText("确定吗？")).toBeTruthy()
    fireEvent.click(screen.getByRole("button", { name: "确认移除" }))
    await waitFor(() => expect(onDone).toHaveBeenCalledTimes(1))
    expect(run).toHaveBeenCalledTimes(1)
    await waitFor(() => expect(screen.queryByRole("alertdialog")).toBeNull())
  })

  it("攻击事件表格：精简版不显示事件编号与行操作，地区显示中文国名，点击行打开详情", () => {
    const incident: Incident = { id: "BAN-1", time: new Date().toISOString(), visitor: "203.0.113.9", region: "DE", rule: null, source: "manual", count: null, disposition: "banned", observe: true, operator: "admin", note: null }
    const onOpen = vi.fn()
    function Harness({ compact }: { compact: boolean }) {
      const table = useIncidentTable({ data: [incident], onOpen, compact, options: { manualPagination: true } })
      return <DataTable table={table} loading={false} empty="空" onRowClick={(i) => onOpen(i.id)} />
    }
    const { rerender } = render(<Harness compact />)
    expect(screen.getAllByRole("cell").length).toBe(6)
    expect(screen.getByText("德国")).toBeTruthy()
    expect(screen.getByText("手动封禁，由 admin 操作")).toBeTruthy()
    expect(screen.getByText("观察")).toBeTruthy()
    expect(screen.queryByText("BAN-1")).toBeNull()
    rerender(<Harness compact={false} />)
    expect(screen.getAllByRole("cell").length).toBe(8) // 多了事件编号与行操作
    expect(screen.getByText("BAN-1")).toBeTruthy()
    expect(screen.getByRole("button", { name: "203.0.113.9 的更多操作" })).toBeTruthy()
    fireEvent.click(screen.getByText("德国"))
    expect(onOpen).toHaveBeenCalledWith("BAN-1")
  })

  it("按列筛选（faceted filter）：选项来自接口，单选，再点取消，计数徽标显示选中项", async () => {
    const seen: unknown[] = []
    function Harness() {
      const [columnFilters, setColumnFilters] = React.useState<{ id: string; value: unknown }[]>([])
      const table = useTable({
        features,
        data: [] as { rule: string }[],
        columns: [{ accessorKey: "rule", header: "触发规则", filterFn: "arrIncludesSome" }],
        manualFiltering: true,
        state: { columnFilters },
        onColumnFiltersChange: (u) => setColumnFilters((old) => (typeof u === "function" ? u(old) : u)),
      })
      seen.push(columnFilters)
      return (
        <DataTableFacetedFilter
          column={table.getColumn("rule")}
          title="触发规则"
          options={[
            { value: "login-burst", label: "登录爆破" },
            { value: "manual", label: "手动封禁" },
          ]}
        />
      )
    }
    render(<Harness />)
    fireEvent.click(screen.getByRole("button", { name: "触发规则" }))
    fireEvent.click(await screen.findByRole("option", { name: "手动封禁" }))
    expect(seen.at(-1)).toEqual([{ id: "rule", value: ["manual"] }])
    expect(within(screen.getByRole("button", { name: /^触发规则/ })).getByText("手动封禁")).toBeTruthy()
    // 接口只接一个值：选另一项是替换，不是追加
    fireEvent.click(screen.getByRole("option", { name: "登录爆破" }))
    expect(seen.at(-1)).toEqual([{ id: "rule", value: ["login-burst"] }])
    expect(screen.getByRole("option", { name: "登录爆破" }).getAttribute("data-checked")).toBe("true")
    // 再点已选中的一项取消
    fireEvent.click(screen.getByRole("option", { name: "登录爆破" }))
    expect(seen.at(-1)).toEqual([])
  })
})

describe("数据表格、设置页分组与全局搜索", () => {
  it("攻击事件：筛选、搜索、每页条数与翻页都作为请求参数交给接口，改筛选回到第一页", async () => {
    const base = (await mockRequest("GET", "/incidents")).data as Awaited<ReturnType<typeof api.incidents>>
    const load = vi.spyOn(api, "incidents").mockImplementation(async (q) => ({ ...base, total: 45, page: Number(q.page), per_page: Number(q.per_page) }))
    const last = () => load.mock.calls.at(-1)![0]
    open("/incidents")
    expect(await screen.findByText("共 45 条，只保留最近 500 条")).toBeTruthy()
    expect(last()).toEqual({ disposition: undefined, rule: undefined, q: undefined, page: 1, per_page: 20 })
    expect(screen.getByText("第 1 / 3 页")).toBeTruthy()

    fireEvent.click(screen.getByRole("button", { name: "下一页" }))
    await waitFor(() => expect(last()).toMatchObject({ page: 2, per_page: 20 }))

    await pick("处置", "已封禁")
    await waitFor(() => expect(last()).toMatchObject({ disposition: "banned", page: 1 }))
    // 再选一项是替换（接口每个筛选只接一个值）
    fireEvent.click(screen.getByRole("option", { name: "已到期" }))
    await waitFor(() => expect(last()).toMatchObject({ disposition: "expired", page: 1 }))
    fireEvent.keyDown(document.activeElement!, { key: "Escape" })

    await pick("触发规则", "登录爆破")
    await waitFor(() => expect(last()).toMatchObject({ disposition: "expired", rule: "login-burst" }))
    fireEvent.keyDown(document.activeElement!, { key: "Escape" })

    fireEvent.click(screen.getByRole("combobox", { name: "每页" }))
    fireEvent.click(await screen.findByRole("option", { name: "50 条" }))
    await waitFor(() => expect(last()).toMatchObject({ page: 1, per_page: 50 }))
    expect(screen.getByText("第 1 / 1 页")).toBeTruthy()

    // 搜索：停止输入片刻后才请求，并写进地址栏
    fireEvent.change(screen.getByRole("textbox", { name: "搜索 IP 或事件编号" }), { target: { value: " 203.0.113 " } })
    await waitFor(() => expect(last()).toMatchObject({ q: "203.0.113", page: 1 }))
    expect(window.location.search).toBe("?q=203.0.113")

    fireEvent.click(screen.getByRole("button", { name: "清除筛选" }))
    await waitFor(() => expect(last()).toEqual({ disposition: undefined, rule: undefined, q: undefined, page: 1, per_page: 50 }))
    expect(window.location.search).toBe("")
  })

  it("封禁列表与操作日志：筛选值作为请求参数；列显隐下拉能隐藏列", async () => {
    const bans = vi.spyOn(api, "bans")
    open("/bans")
    expect(await screen.findByText("共 5 个访客正在被封禁")).toBeTruthy()
    await pick("触发规则", "手动封禁")
    await waitFor(() => expect(bans.mock.calls.at(-1)![0]).toEqual({ rule: "manual", q: undefined }))
    expect(await screen.findByText("共 1 个访客正在被封禁")).toBeTruthy()
    fireEvent.keyDown(document.activeElement!, { key: "Escape" })

    // 列显隐：照官方 View 下拉
    expect(screen.getByRole("columnheader", { name: "地区" })).toBeTruthy()
    fireEvent.keyDown(screen.getByRole("button", { name: "显示列" }), { key: "Enter" })
    fireEvent.click(await screen.findByRole("menuitemcheckbox", { name: "地区" }))
    await waitFor(() => expect(screen.queryByRole("columnheader", { name: "地区" })).toBeNull())
  })

  it("操作日志：操作类型筛选作为 action 参数", async () => {
    const audit = vi.spyOn(api, "audit")
    open("/audit")
    expect(await screen.findByText("由「观察」改为「拦截」")).toBeTruthy()
    await pick("操作类型", "解封")
    await waitFor(() => expect(audit.mock.calls.at(-1)![0]).toEqual({ action: "unban", page: 1, per_page: 20 }))
    expect(await screen.findByText("共 1 条，只保留最近 500 条")).toBeTruthy()
  })

  it("设置页：切换分组不丢草稿，有草稿的分组标「未保存」，放弃后全部还原", async () => {
    open("/settings")
    fireEvent.click(await screen.findByRole("radio", { name: "观察模式" }))
    expect(navItem("运行模式").textContent).toContain("未保存")

    await section("累犯加长")
    fireEvent.change(screen.getByLabelText("加长倍数"), { target: { value: "4" } })
    await section("拦截响应")
    fireEvent.click(screen.getByLabelText("访客 IP"))
    await section("防护规则")
    expect(screen.getAllByRole("button", { name: "编辑" }).length).toBe(6)

    // 切回来，草稿都还在
    await section("运行模式")
    expect(screen.getByRole("radio", { name: "观察模式" }).getAttribute("aria-checked")).toBe("true")
    await section("累犯加长")
    expect((screen.getByLabelText("加长倍数") as HTMLInputElement).value).toBe("4")
    await section("拦截响应")
    expect(screen.getByLabelText("访客 IP").getAttribute("aria-checked")).toBe("false")
    for (const name of ["运行模式", "累犯加长", "拦截响应"]) expect(navItem(name).textContent).toContain("未保存")
    expect(navItem("防护规则").textContent).not.toContain("未保存")

    fireEvent.click(screen.getByRole("button", { name: "放弃修改" }))
    expect(screen.getByLabelText("访客 IP").getAttribute("aria-checked")).toBe("true")
    await section("累犯加长")
    expect((screen.getByLabelText("加长倍数") as HTMLInputElement).value).toBe("2")
    expect(screen.queryByText("未保存")).toBeNull()
  })

  it("设置页：保存时 422 的字段不在当前分组，自动切到出错的分组", async () => {
    open("/settings")
    await section("累犯加长")
    fireEvent.change(await screen.findByLabelText("加长倍数"), { target: { value: "99" } })
    await section("运行模式")
    fireEvent.click(screen.getByRole("button", { name: "保存修改" }))
    expect(await screen.findByText("可填 2 到 10")).toBeTruthy()
    expect(navItem("累犯加长").getAttribute("aria-current")).toBe("true")
  })

  it("全局搜索：Ctrl+K 打开，可跳到页面；输入 IP 或事件编号时跳到对应页并带上搜索词", async () => {
    const bans = vi.spyOn(api, "bans")
    const incidents = vi.spyOn(api, "incidents")
    open("/")
    expect(await screen.findByText("1,341")).toBeTruthy()

    // 跳到页面
    act(() => {
      fireEvent.keyDown(document, { key: "k", ctrlKey: true })
    })
    fireEvent.click(await screen.findByRole("option", { name: "操作日志" }))
    await waitFor(() => expect(window.location.pathname).toBe("/fail2ban/audit"))
    expect(await screen.findByText("由「观察」改为「拦截」")).toBeTruthy()

    // 在封禁列表中搜索
    fireEvent.click(screen.getByRole("button", { name: "搜索" }))
    const input = await screen.findByRole("combobox")
    fireEvent.change(input, { target: { value: "203.0.113.47" } })
    expect(screen.getByRole("option", { name: "在攻击事件中搜索「203.0.113.47」" })).toBeTruthy()
    fireEvent.click(screen.getByRole("option", { name: "在封禁列表中搜索「203.0.113.47」" }))
    await waitFor(() => expect(window.location.pathname + window.location.search).toBe("/fail2ban/bans?q=203.0.113.47"))
    expect(await screen.findByText("共 1 个访客正在被封禁")).toBeTruthy()
    expect(bans.mock.calls.at(-1)![0]).toEqual({ rule: undefined, q: "203.0.113.47" })
    expect((screen.getByRole("textbox", { name: "搜索 IP" }) as HTMLInputElement).value).toBe("203.0.113.47")

    // 在攻击事件中按事件编号搜索；不像 IP 或事件编号的输入不给这两项
    act(() => {
      fireEvent.keyDown(document, { key: "k", metaKey: true })
    })
    const again = await screen.findByRole("combobox")
    fireEvent.change(again, { target: { value: "设置" } })
    expect(screen.queryByRole("option", { name: /在攻击事件中搜索/ })).toBeNull()
    fireEvent.change(again, { target: { value: "BAN-20261106-7K2M9Q" } })
    fireEvent.click(screen.getByRole("option", { name: "在攻击事件中搜索「BAN-20261106-7K2M9Q」" }))
    await waitFor(() => expect(window.location.pathname + window.location.search).toBe("/fail2ban/incidents?q=BAN-20261106-7K2M9Q"))
    await waitFor(() => expect(incidents.mock.calls.at(-1)![0]).toMatchObject({ q: "BAN-20261106-7K2M9Q", page: 1 }))
    expect(await screen.findByText("共 1 条，只保留最近 500 条")).toBeTruthy()
  })
})
