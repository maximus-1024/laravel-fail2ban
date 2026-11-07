<?php

namespace Maximus\Fail2Ban\Contracts;

/**
 * 操作日志：列表 fail2ban:audit，新的在前，只留 HISTORY_LIMIT 条。
 */
interface AuditRepository
{
    /**
     * 操作来源：面板与命令行。
     */
    public const VIA_PANEL = 'panel';

    public const VIA_CONSOLE = 'console';

    /**
     * 写一条操作日志。
     *
     * @param  string  $action  unban | ban | allow_add | allow_remove | settings | mode
     * @param  string|array|null  $detail  给人看的说明，或结构化内容（例如 {text: 说明, old: 旧值, new: 新值}）
     * @param  string|null  $via  操作来源 VIA_PANEL | VIA_CONSOLE；null 表示未注明
     * @return array{time: int, operator: string, action: string, target: ?string, detail: string|array|null, via: ?string}
     */
    public function record(string $operator, string $action, ?string $target = null, string|array|null $detail = null, ?string $via = null): array;

    /**
     * 分页，新的在前；$action 不为 null 时只看这一类。页码与每页条数由调用方限定。
     *
     * @return array{data: list<array{time: int, operator: string, action: string, target: ?string, detail: string|array|null, via: ?string}>, total: int, page: int, per_page: int, history_limit: int}
     */
    public function paginate(?string $action = null, int $page = 1, int $perPage = 20): array;
}
