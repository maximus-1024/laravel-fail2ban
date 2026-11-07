import type { Column, RowData } from "@tanstack/react-table"
import { PlusCircleIcon } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Command, CommandEmpty, CommandGroup, CommandInput, CommandItem, CommandList, CommandSeparator } from "@/components/ui/command"
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover"
import { Separator } from "@/components/ui/separator"
import type { Features } from "./features"

export interface FilterOption {
  label: string
  value: string
}

/**
 * 按列筛选：照官方 Tasks 示例的 faceted filter（Popover + Command + Badge）。
 * 接口每个筛选只接一个值，所以这里是单选：选中另一项会替换，再点已选中的一项取消。
 * 筛选值仍按官方写法存成数组，接口支持多选后只需去掉替换这一步。
 */
export function DataTableFacetedFilter<TData extends RowData>({
  column,
  title,
  options,
}: {
  column?: Column<Features, TData>
  title: string
  options: FilterOption[]
}) {
  const selected = new Set((column?.getFilterValue() as string[] | undefined) ?? [])
  const chosen = options.filter((o) => selected.has(o.value))

  return (
    <Popover>
      <PopoverTrigger asChild>
        <Button variant="outline" size="sm">
          <PlusCircleIcon data-icon="inline-start" />
          {title}
          {chosen.length > 0 && (
            <>
              <Separator orientation="vertical" className="mx-0.5 data-vertical:h-4 data-vertical:self-auto" />
              {chosen.map((o) => (
                <Badge key={o.value} variant="secondary">
                  {o.label}
                </Badge>
              ))}
            </>
          )}
        </Button>
      </PopoverTrigger>
      <PopoverContent className="w-56 p-0" align="start">
        <Command>
          <CommandInput placeholder={title} />
          <CommandList>
            <CommandEmpty>没有匹配的选项</CommandEmpty>
            <CommandGroup>
              {options.map((o) => {
                const isSelected = selected.has(o.value)
                return (
                  <CommandItem key={o.value} value={o.label} data-checked={isSelected} onSelect={() => column?.setFilterValue(isSelected ? undefined : [o.value])}>
                    {o.label}
                  </CommandItem>
                )
              })}
            </CommandGroup>
            {selected.size > 0 && (
              <>
                <CommandSeparator />
                <CommandGroup>
                  <CommandItem onSelect={() => column?.setFilterValue(undefined)}>
                    清除筛选
                  </CommandItem>
                </CommandGroup>
              </>
            )}
          </CommandList>
        </Command>
      </PopoverContent>
    </Popover>
  )
}
