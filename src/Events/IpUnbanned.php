<?php

namespace Maximus\Fail2Ban\Events;

/**
 * 一个封禁被提前解除了。
 *
 * 每个被解除的封禁恰好发出一次，在解除写进 Redis 之后；解封时访客其实没有被封
 * （BanRepository::unban() 返回 null）时不发。三种原因：
 *
 *  - REASON_MANUAL（manual）：在面板或用命令 fail2ban:unban 解封；
 *  - REASON_ALLOWLISTED（allowlisted）：加入白名单时连带解除落在条目里的封禁；
 *  - REASON_OBSERVATION_CLEARED（observation_cleared）：运行模式切到拦截时解除观察期间产生的自动封禁。
 *
 * 封禁到期是 Redis 键自然过期，没有进程在跑，所以到期不发任何事件。
 * 手动封禁覆盖已有封禁时，被覆盖的那次也不发本事件（新的那次发 IpBanned）。
 *
 * 载荷都是普通数组与字符串，可以安全地交给队列监听器序列化。
 */
class IpUnbanned
{
    public const REASON_MANUAL = 'manual';

    public const REASON_ALLOWLISTED = 'allowlisted';

    public const REASON_OBSERVATION_CLEARED = 'observation_cleared';

    /**
     * Create a new event instance.
     *
     * @param  string  $visitor  访客键（IPv4 地址，或 IPv6 的 64 位网段）
     * @param  array  $ban  被解除的封禁记录（BanRepository::unban() 的返回值，形状见 Contracts\BanRepository 的类注释）
     * @param  string  $actor  操作人（Fail2Ban::actor() 的结果）
     * @param  string  $via  操作来源：'panel' | 'console'（AuditRepository::VIA_PANEL | VIA_CONSOLE）
     * @param  string  $reason  self::REASON_MANUAL | REASON_ALLOWLISTED | REASON_OBSERVATION_CLEARED
     */
    public function __construct(
        public string $visitor,
        public array $ban,
        public string $actor,
        public string $via,
        public string $reason,
    ) {
    }
}
