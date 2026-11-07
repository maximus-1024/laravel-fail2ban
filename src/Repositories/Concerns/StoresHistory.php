<?php

namespace Maximus\Fail2Ban\Repositories\Concerns;

/**
 * 攻击事件与操作日志共用的历史列表：新的放最前，只留 HISTORY_LIMIT 条，读取与分页。
 *
 * 用它的类同时用 InteractsWithRedis。
 */
trait StoresHistory
{
    /**
     * 写一条，放在最前；超过 HISTORY_LIMIT 的最旧条目被丢弃。一次往返。
     */
    protected function push(string $key, array $entry): void
    {
        $this->pipeline(function ($pipe) use ($key, $entry) {
            $pipe->lpush($key, $this->encode($entry));
            $pipe->ltrim($key, 0, $this->historyLimit() - 1);
        });
    }

    /**
     * 全部条目，新的在前；解不开的条目跳过。
     *
     * @return list<array>
     */
    protected function history(string $key): array
    {
        return array_values(array_filter(
            array_map(fn ($json) => json_decode($json, true), $this->connection()->lrange($key, 0, -1) ?: []),
            'is_array',
        ));
    }

    /**
     * 一页，外加总条数与 HISTORY_LIMIT（面板据此显示「只保留最近 N 条」）。页码与每页条数由调用方限定。
     *
     * @param  list<array>  $entries
     * @return array{data: list<array>, total: int, page: int, per_page: int, history_limit: int}
     */
    protected function paginateHistory(array $entries, int $page, int $perPage): array
    {
        return [
            'data' => collect($entries)->forPage($page, $perPage)->values()->all(),
            'total' => count($entries),
            'page' => $page,
            'per_page' => $perPage,
            'history_limit' => $this->historyLimit(),
        ];
    }

    /**
     * HISTORY_LIMIT：两类历史各自保留的条数。
     */
    protected function historyLimit(): int
    {
        return max(1, (int) config('fail2ban.history_limit', 500));
    }
}
