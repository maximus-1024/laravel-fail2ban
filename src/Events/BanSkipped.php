<?php

namespace Maximus\Fail2Ban\Events;

/**
 * 访客达到了一条动作为封禁的规则的出现次数，但被宿主程序豁免（Fail2Ban::isExempt()），没有封。
 *
 * 同一条规则在同一个时间范围内只发出一次（命中条数恰好达到出现次数的那一次），
 * 与那条处置为 exempted 的攻击事件一一对应。
 *
 * 载荷是普通数组，可以安全地交给队列监听器序列化。
 */
class BanSkipped
{
    /**
     * Create a new event instance.
     *
     * @param  array  $incident  写进历史的攻击事件，形状见 Contracts\IncidentRepository 的类注释
     *                           （disposition 为 exempted；含 visitor、ip、region、rule、count、observe、
     *                           user_agent、first_hit_at、other_rules、requests）
     */
    public function __construct(
        public array $incident,
    ) {
    }
}
