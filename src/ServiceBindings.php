<?php

namespace Maximus\Fail2Ban;

/**
 * 存储契约与 Redis 实现的绑定（照 Horizon 的 ServiceBindings）。
 */
trait ServiceBindings
{
    /**
     * All of the service bindings for Fail2Ban.
     *
     * @var array<class-string, class-string>
     */
    public $serviceBindings = [
        Contracts\AllowlistRepository::class => Repositories\RedisAllowlistRepository::class,
        Contracts\AuditRepository::class => Repositories\RedisAuditRepository::class,
        Contracts\BanRepository::class => Repositories\RedisBanRepository::class,
        Contracts\IncidentRepository::class => Repositories\RedisIncidentRepository::class,
        Contracts\SettingsRepository::class => Repositories\RedisSettingsRepository::class,
        Contracts\StatsRepository::class => Repositories\RedisStatsRepository::class,
    ];
}
