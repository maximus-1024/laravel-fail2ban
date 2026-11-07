<?php

namespace Maximus\Fail2Ban\Events;

/**
 * 一次封禁真的生效了：自动封禁或手动封禁（面板或命令 fail2ban:ban）。
 *
 * 用 $ban['source']（'auto' | 'manual'）区分；手动封禁的 $ban['operator'] 是操作人、$via 是操作来源。
 *
 * 每次封禁恰好发出一次，在封禁写进 Redis 之后。自动封禁时访客已被封（BanRepository::ban() 返回 null）不发；
 * 手动封禁以这次为准覆盖已有封禁，每次都发。运行模式为观察时同样发出，$ban['observe'] 与 $incident['observe'] 为 true。
 *
 * 载荷都是普通数组，可以安全地交给队列监听器序列化。
 */
class IpBanned
{
    /**
     * Create a new event instance.
     *
     * @param  array  $ban  封禁记录，形状见 Contracts\BanRepository 的类注释
     *                      （visitor、incident、rule、count、offense、ip、region、user_agent、observe、
     *                      banned_at、unban_at、ban_minutes、other_rules、requests 等）
     * @param  array  $incident  写进历史的攻击事件，形状见 Contracts\IncidentRepository 的类注释
     *                           （id 与 $ban['incident'] 相同，disposition 为 banned）
     * @param  string|null  $via  手动封禁的操作来源 'panel' | 'console'（AuditRepository::VIA_PANEL | VIA_CONSOLE）；自动封禁为 null
     */
    public function __construct(
        public array $ban,
        public array $incident,
        public ?string $via = null,
    ) {
    }
}
