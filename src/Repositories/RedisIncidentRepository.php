<?php

namespace Maximus\Fail2Ban\Repositories;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Redis\Factory as RedisFactory;
use InvalidArgumentException;
use Maximus\Fail2Ban\Contracts\IncidentRepository;
use Maximus\Fail2Ban\LuaScripts;
use Maximus\Fail2Ban\Repositories\Concerns\FiltersRecords;
use Maximus\Fail2Ban\Repositories\Concerns\InteractsWithRedis;
use Maximus\Fail2Ban\Repositories\Concerns\StoresHistory;
use Maximus\Fail2Ban\Support\Text;

class RedisIncidentRepository implements IncidentRepository
{
    use FiltersRecords, InteractsWithRedis, StoresHistory;

    public const KEY = 'fail2ban:events';

    /**
     * 可存储的处置。'expired' 只在读取时推出来。
     */
    public const DISPOSITIONS = ['banned', 'unbanned', 'exempted', 'recorded'];

    /**
     * Create a new repository instance.
     */
    public function __construct(RedisFactory $redis)
    {
        $this->redis = $redis;
    }

    public function nextId(): string
    {
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
        $suffix = '';

        for ($i = 0; $i < 6; $i++) {
            $suffix .= $alphabet[random_int(0, 35)];
        }

        return 'BAN-'.CarbonImmutable::now()->format('Ymd').'-'.$suffix;
    }

    public function record(array $incident): array
    {
        $incident = $this->normalize($incident);

        $this->push(self::KEY, $incident);

        return $this->present($incident);
    }

    public function find(string $id): ?array
    {
        foreach ($this->load() as $incident) {
            if ($incident['id'] === $id) {
                return $incident;
            }
        }

        return null;
    }

    public function paginate(array $filters = [], int $page = 1, int $perPage = 20): array
    {
        return $this->paginateHistory($this->filterRecords($this->load(), $filters, ['id', 'visitor', 'ip']), $page, $perPage);
    }

    public function markUnbanned(string $id): bool
    {
        return (int) $this->script(LuaScripts::replaceInList(), [self::KEY], [
            '{"id":'.$this->encode($id).',',
            '"disposition":"banned"',
            '"disposition":"unbanned"',
        ]) === 1;
    }

    /**
     * 全部事件，新的在前。
     *
     * @return list<array>
     */
    protected function load(): array
    {
        return array_map(
            fn (array $incident) => $this->present($incident),
            array_values(array_filter($this->history(self::KEY), fn (array $incident) => isset($incident['id']))),
        );
    }

    /**
     * 读取时推出「已到期」。
     */
    protected function present(array $incident): array
    {
        if ($incident['disposition'] === 'banned'
            && $incident['unban_at'] !== null
            && $incident['unban_at'] <= CarbonImmutable::now()->getTimestamp()) {
            $incident['disposition'] = 'expired';
        }

        return $incident;
    }

    /**
     * 只留约定的字段，固定顺序（id 在最前，markUnbanned() 按开头定位）。
     */
    protected function normalize(array $incident): array
    {
        if (! in_array($incident['disposition'] ?? null, self::DISPOSITIONS, true)) {
            throw new InvalidArgumentException('The incident disposition must be one of: '.implode(', ', self::DISPOSITIONS).'.');
        }

        if (! isset($incident['visitor']) || $incident['visitor'] === '') {
            throw new InvalidArgumentException('The incident visitor is required.');
        }

        $int = fn (string $field) => isset($incident[$field]) ? (int) $incident[$field] : null;
        $str = fn (string $field) => isset($incident[$field]) && $incident[$field] !== '' ? (string) $incident[$field] : null;

        return [
            'id' => $str('id') ?? $this->nextId(),
            'time' => $int('time') ?? CarbonImmutable::now()->getTimestamp(),
            'visitor' => (string) $incident['visitor'],
            'ip' => $str('ip'),
            'region' => $str('region'),
            'rule' => $str('rule'),
            'source' => ($incident['source'] ?? 'auto') === 'manual' ? 'manual' : 'auto',
            'count' => $int('count'),
            'disposition' => $incident['disposition'],
            'observe' => (bool) ($incident['observe'] ?? false),
            'operator' => $str('operator'),
            'note' => $str('note'),
            'user_agent' => Text::userAgent($incident['user_agent'] ?? null),
            'first_hit_at' => $int('first_hit_at'),
            'banned_at' => $int('banned_at'),
            'unban_at' => $int('unban_at'),
            'ban_minutes' => $int('ban_minutes'),
            'offense' => $int('offense'),
            'other_rules' => array_map('intval', (array) ($incident['other_rules'] ?? [])),
            'requests' => array_values(array_map(fn ($request) => [
                'time' => (int) ($request['time'] ?? 0),
                'method' => $request['method'] ?? null,
                'path' => $request['path'] ?? null,
            ], array_filter((array) ($incident['requests'] ?? []), 'is_array'))),
        ];
    }
}
