<?php

namespace Maximus\Fail2Ban\Repositories;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Redis\Factory as RedisFactory;
use Maximus\Fail2Ban\Contracts\AuditRepository;
use Maximus\Fail2Ban\Repositories\Concerns\InteractsWithRedis;
use Maximus\Fail2Ban\Repositories\Concerns\StoresHistory;

class RedisAuditRepository implements AuditRepository
{
    use InteractsWithRedis, StoresHistory;

    public const KEY = 'fail2ban:audit';

    /**
     * Create a new repository instance.
     */
    public function __construct(RedisFactory $redis)
    {
        $this->redis = $redis;
    }

    public function record(string $operator, string $action, ?string $target = null, string|array|null $detail = null, ?string $via = null): array
    {
        $entry = [
            'time' => CarbonImmutable::now()->getTimestamp(),
            'operator' => $operator,
            'action' => $action,
            'target' => $target,
            'detail' => $detail,
            'via' => $via,
        ];

        $this->push(self::KEY, $entry);

        return $entry;
    }

    public function paginate(?string $action = null, int $page = 1, int $perPage = 20): array
    {
        $entries = $this->history(self::KEY);

        if (filled($action)) {
            $entries = array_values(array_filter($entries, fn (array $entry) => ($entry['action'] ?? null) === $action));
        }

        return $this->paginateHistory($entries, $page, $perPage);
    }
}
