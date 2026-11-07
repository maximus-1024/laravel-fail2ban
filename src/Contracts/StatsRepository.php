<?php

namespace Maximus\Fail2Ban\Contracts;

/**
 * 总览统计：按小时的计数 fail2ban:stats:{YmdH}，当天排行 fail2ban:top:{类别}:{Ymd}。
 *
 * 小时与日期按应用时区。所有键带 STATS_DAYS 的过期时间；排行每种只留前 200 名。
 * 每个 increment* 方法是一次往返（一个 Lua 脚本）。规则命中的统计（小时计数与三个排行）
 * 由 BanRepository::recordHits() 与记命中合在同一个管道里写。
 */
interface StatsRepository
{
    /**
     * 排行的三个类别：攻击源（访客键）、攻击目标（路径）、来源地区。
     */
    public const CATEGORIES = ['ip', 'target', 'region'];

    /**
     * 一次拦截：本小时拦截数加一。
     */
    public function incrementBlocked(): void;

    /**
     * 一次封禁（自动或手动）：本小时新增封禁数加一。
     */
    public function incrementBans(): void;

    /**
     * 最近 $hours 个小时（含当前小时）的趋势，从旧到新，每小时一项。
     *
     * @return list<array{hour: int, hits: int, blocked: int, bans: int, rules: array<string, int>}>
     *                                                                                                hour 是这一小时开始的时间戳；rules 含配置里的每条规则
     */
    public function trend(int $hours = 24): array;

    /**
     * 排行，按次数降序。$days 为 1 时只看今天，大于 1 时把最近几天（含今天）的合并。
     *
     * 每天只留前 200 名，合并几天时，某天没进前 200 的成员在那天的次数不计，所以合并后的排行在
     * 满 200 名之后是近似值（靠前的几名不受影响）。
     *
     * @param  string  $category  ip | target | region
     * @return list<array{key: string, count: int}>
     */
    public function top(string $category, int $limit = 10, int $days = 1): array;
}
