/**
 * 每页顶部的标题区：照 shadcn-admin 的页面标题写法（src/features/tasks/index.tsx 第 24–31 行、
 * src/features/dashboard/index.tsx 第 36 行）—— h1 标题、一句说明，右边放这一页的主要操作。
 * 标题的字号字重类是照抄参考实现的排版类，属于「不写自定义样式」的唯一例外。
 */
export function PageHeader({ title, description, actions }: { title: string; description: React.ReactNode; actions?: React.ReactNode }) {
  return (
    <div className="flex flex-wrap items-end justify-between gap-2">
      <div className="flex min-w-60 flex-1 flex-col gap-1">
        <h1 className="text-2xl font-bold tracking-tight">{title}</h1>
        <p className="text-muted-foreground">{description}</p>
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  )
}
