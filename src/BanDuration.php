<?php

namespace Maximus\Fail2Ban;

/**
 * 自动封禁时长，纯函数，单位分钟。
 */
class BanDuration
{
    /**
     * 按已封次数排开的时长表：第 i 项是「此前已被封 i 次」时的时长，最后一项之后都等于最后一项。
     *
     * - REPEAT_BAN 关闭，或此前没有被自动封过：就是 RULE_BAN；
     * - 否则：RULE_BAN × REPEAT_FACTOR ^ 已封次数，不超过 REPEAT_MAX；
     * - RULE_BAN 本身比 REPEAT_MAX 长时按 RULE_BAN。
     *
     * 表的长度有上限（到封顶为止，最多十几项），所以可以整张交给 Lua 脚本，
     * 让脚本在读累犯次数的同一次原子操作里查表——计算只在这里写一次。
     *
     * @param  int  $ruleBan  触发规则的 RULE_BAN（分钟）
     * @param  array{enabled: bool, factor: int, max_days: int, keep_days?: int}  $repeat  累犯加长设置
     * @return non-empty-list<int>
     */
    public static function schedule(int $ruleBan, array $repeat): array
    {
        $ruleBan = max(1, $ruleBan);
        $factor = (int) ($repeat['factor'] ?? 2);
        $cap = max(1, (int) ($repeat['max_days'] ?? 1)) * 1440;

        if (! ($repeat['enabled'] ?? false) || $factor < 2) {
            return [$ruleBan];
        }

        $schedule = [$ruleBan];

        for ($minutes = $ruleBan; $minutes < $cap;) {
            $minutes = min($minutes * $factor, $cap);
            $schedule[] = $minutes;
        }

        return $schedule;
    }
}
