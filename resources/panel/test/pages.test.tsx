import { fireEvent, render, screen, waitFor, within } from "@testing-library/react"
import { afterEach, describe, expect, it, vi } from "vitest"
import { App } from "@/app"
import { ConfirmButton } from "@/components/confirm-button"
import { IncidentRow, RuleSelect } from "@/components/shared"
import { FRESH_MS, StatusProvider } from "@/components/status"
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
    expect(await screen.findByText("防护规则")).toBeTruthy()
    for (const name of ["404 扫描", "敏感文件探测", "扫描器特征", "攻击特征", "已知漏洞探测", "登录爆破"]) expect(screen.getByText(name)).toBeTruthy()
    expect(screen.getAllByRole("button", { name: "编辑" }).length).toBe(6)
    expect(screen.getByText(/以404 扫描为例：第 1 次封 30 分钟，第 2 次封 1 小时/)).toBeTruthy()
    // 取值范围来自接口的 limits
    expect(screen.getByText(/每多被封一次，时长乘以这个数。可填 2 到 10。/)).toBeTruthy()
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
    expect(await screen.findByText("防护规则")).toBeTruthy()
    expect(load).toHaveBeenCalledTimes(1)

    fireEvent.click(screen.getByRole("radio", { name: "观察模式" }))
    const save = screen.getByRole("button", { name: "保存修改" }) as HTMLButtonElement
    expect(save.disabled).toBe(false)

    fireEvent.click(screen.getAllByRole("button", { name: "编辑" })[0])
    const sheet = await screen.findByRole("dialog")
    fireEvent.change(within(sheet).getByLabelText("封禁时长，单位分钟"), { target: { value: "45" } })
    fireEvent.click(within(sheet).getByRole("button", { name: "确定" }))
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull())
    expect(screen.getByText("45 分钟")).toBeTruthy()
    expect(save.disabled).toBe(false)
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
    const message = (await screen.findByLabelText("给访客的提示文字")) as HTMLTextAreaElement
    expect(message.maxLength).toBe(20)
    expect(screen.getByText("最多 20 个字。")).toBeTruthy()

    // 浏览器会挡住超长输入；这里绕过它，确认后端 422 的 response.message 显示在字段下
    fireEvent.change(message, { target: { value: "字".repeat(501) } })
    fireEvent.click(screen.getByRole("button", { name: "保存修改" }))
    const card = message.closest("[data-slot=card]") as HTMLElement
    expect(await within(card).findByText("最多 500 个字")).toBeTruthy()
    expect(message.getAttribute("aria-invalid")).toBe("true")
  })

  it("提示文字：接口没给 limits.message 时不限制长度", async () => {
    const base = (await mockRequest("GET", "/settings")).data as Settings
    const { message: _omit, ...limits } = base.limits
    vi.spyOn(api, "settings").mockResolvedValue({ ...base, limits })
    open("/settings")
    const message = await screen.findByLabelText("给访客的提示文字")
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
    fireEvent.change(screen.getByLabelText("加长倍数"), { target: { value: "3" } })
    fireEvent.change(screen.getByLabelText("给访客的提示文字"), { target: { value: "草稿" } })

    // 别人从命令行改了模式与倍数，命中数也变了
    resolve({ ...base, mode: "off", repeat: { ...base.repeat, factor: 5 }, rules: base.rules.map((r, i) => (i === 0 ? { ...r, hits_24h: 9999 } : r)) })
    expect(await screen.findByText("9,999")).toBeTruthy()
    expect(screen.getByText("乘以 5")).toBeTruthy()
    expect(screen.getByRole("radio", { name: "观察模式" }).getAttribute("aria-checked")).toBe("true")
    expect((screen.getByLabelText("加长倍数") as HTMLInputElement).value).toBe("3")
    expect((screen.getByLabelText("给访客的提示文字") as HTMLTextAreaElement).value).toBe("草稿")
    expect((screen.getByRole("button", { name: "保存修改" }) as HTMLButtonElement).disabled).toBe(false)
  })

  it("操作日志：表格与筛选", async () => {
    open("/audit")
    expect(await screen.findByText("封 24 小时。备注：反复用错误签名请求代付接口")).toBeTruthy()
    expect(screen.getByText("由「观察」改为「拦截」")).toBeTruthy()
    expect(screen.getByRole("combobox", { name: "操作类型" })).toBeTruthy()
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
    fireEvent.click(screen.getByRole("combobox", { name: "触发规则" }))
    const listbox = await screen.findByRole("listbox")
    expect(within(listbox).getByText("登录爆破")).toBeTruthy()
    expect(within(listbox).getAllByRole("option").length).toBe(8) // 全部 + 6 条规则 + 手动封禁
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

  it("IncidentRow：事件编号列可选，地区显示中文国名，点击打开详情", () => {
    const incident: Incident = { id: "BAN-1", time: new Date().toISOString(), visitor: "203.0.113.9", region: "DE", rule: null, source: "manual", count: null, disposition: "banned", observe: true, operator: "admin", note: null }
    const onOpen = vi.fn()
    const { rerender } = render(
      <table>
        <tbody>
          <IncidentRow incident={incident} onOpen={onOpen} />
        </tbody>
      </table>,
    )
    expect(screen.getAllByRole("cell").length).toBe(6)
    expect(screen.getByText("德国")).toBeTruthy()
    expect(screen.getByText("手动封禁，由 admin 操作")).toBeTruthy()
    expect(screen.getByText("观察")).toBeTruthy()
    rerender(
      <table>
        <tbody>
          <IncidentRow incident={incident} showId onOpen={onOpen} />
        </tbody>
      </table>,
    )
    expect(screen.getAllByRole("cell").length).toBe(7)
    expect(screen.getByText("BAN-1")).toBeTruthy()
    fireEvent.click(screen.getByText("德国"))
    expect(onOpen).toHaveBeenCalledWith("BAN-1")
  })

  it("RuleSelect：全部、接口返回的规则与手动封禁，选中后回调取值", async () => {
    const onChange = vi.fn()
    render(
      <StatusProvider>
        <RuleSelect value="all" onChange={onChange} />
      </StatusProvider>,
    )
    // 等设置接口返回规则清单
    await waitFor(() => expect(screen.getByRole("combobox", { name: "触发规则" }).textContent).toBe("全部规则"))
    fireEvent.click(screen.getByRole("combobox", { name: "触发规则" }))
    const listbox = await screen.findByRole("listbox")
    await waitFor(() => expect(within(listbox).getAllByRole("option").length).toBe(8))
    fireEvent.click(within(listbox).getByRole("option", { name: "手动封禁" }))
    expect(onChange).toHaveBeenCalledWith("manual")
  })
})
