<?php

namespace Maximus\Fail2Ban\Repositories;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Redis\Factory as RedisFactory;
use InvalidArgumentException;
use Maximus\Fail2Ban\Contracts\StatsRepository;
use Maximus\Fail2Ban\LuaScripts;
use Maximus\Fail2Ban\Repositories\Concerns\InteractsWithRedis;

class RedisStatsRepository implements StatsRepository
{
    use InteractsWithRedis;

    /**
     * 每种排行只留前多少名。
     */
    public const TOP_KEEP = 200;

    /**
     * Create a new repository instance.
     */
    public function __construct(RedisFactory $redis)
    {
        $this->redis = $redis;
    }

    /**
     * 一次规则命中的统计（本小时该规则的命中数加一，并累加当天三个排行，为 null 的类别跳过）的脚本调用
     * [脚本, KEYS, ARGV]。RedisBanRepository::recordHits() 把它与记命中排进同一个管道。
     *
     * @return array{0: string, 1: list<string>, 2: list<string|int>}
     */
    public function incrementHitCommand(string $rule, string $visitor, ?string $target = null, ?string $region = null): array
    {
        return $this->incrementCommand('hits:'.$rule, array_filter(
            ['ip' => $visitor, 'target' => $target, 'region' => $region],
            fn ($member) => $member !== null && $member !== ''
        ));
    }

    public function incrementBlocked(): void
    {
        $this->increment('blocked');
    }

    public function incrementBans(): void
    {
        $this->increment('bans');
    }

    public function trend(int $hours = 24): array
    {
        $hours = max(1, $hours);
        $current = CarbonImmutable::now()->startOfHour();
        $slots = [];

        for ($i = $hours - 1; $i >= 0; $i--) {
            $slots[] = $current->subHours($i);
        }

        $results = $this->pipeline(function ($pipe) use ($slots) {
            foreach ($slots as $hour) {
                $pipe->hgetall($this->statsKey($hour));
            }
        });

        $rules = array_keys((array) config('fail2ban.rules'));

        return array_map(function (CarbonImmutable $hour, $fields) use ($rules) {
            $fields = is_array($fields) ? $fields : [];
            $perRule = array_fill_keys($rules, 0);

            foreach ($fields as $field => $count) {
                if (str_starts_with($field, 'hits:')) {
                    $perRule[substr($field, 5)] = (int) $count;
                }
            }

            return [
                'hour' => $hour->getTimestamp(),
                'hits' => array_sum($perRule),
                'blocked' => (int) ($fields['blocked'] ?? 0),
                'bans' => (int) ($fields['bans'] ?? 0),
                'rules' => $perRule,
            ];
        }, $slots, $results);
    }

    public function top(string $category, int $limit = 10, int $days = 1): array
    {
        if (! in_array($category, self::CATEGORIES, true)) {
            throw new InvalidArgumentException("Unknown ranking category [{$category}].");
        }

        $today = CarbonImmutable::now()->startOfDay();
        $days = max(1, $days);

        $results = $this->pipeline(function ($pipe) use ($category, $today, $days) {
            for ($i = 0; $i < $days; $i++) {
                $pipe->zrevrange($this->topKey($category, $today->subDays($i)), 0, self::TOP_KEEP - 1, true);
            }
        });

        $merged = [];

        foreach ($results as $members) {
            foreach (is_array($members) ? $members : [] as $member => $score) {
                $merged[(string) $member] = ($merged[(string) $member] ?? 0) + (int) $score;
            }
        }

        uksort($merged, fn ($a, $b) => [$merged[$b], $a] <=> [$merged[$a], $b]);

        $top = [];

        foreach (array_slice($merged, 0, max(0, $limit), true) as $key => $count) {
            $top[] = ['key' => (string) $key, 'count' => $count];
        }

        return $top;
    }

    /**
     * 一次脚本调用（一次往返）：本小时的一个字段加一，并给各排行加一，全部设过期。
     *
     * @param  array<string, string>  $tops  类别 => 成员
     */
    protected function increment(string $field, array $tops = []): void
    {
        $this->script(...$this->incrementCommand($field, $tops));
    }

    /**
     * increment() 的脚本调用 [脚本, KEYS, ARGV]。
     *
     * @param  array<string, string>  $tops  类别 => 成员
     * @return array{0: string, 1: list<string>, 2: list<string|int>}
     */
    protected function incrementCommand(string $field, array $tops = []): array
    {
        $now = CarbonImmutable::now();
        $hour = $now->startOfHour();
        $day = $now->startOfDay();

        return [LuaScripts::incrementStats(), [
            $this->statsKey($hour),
            ...array_map(fn ($category) => $this->topKey($category, $day), array_keys($tops)),
        ], [
            $field,
            $hour->addDays($this->days())->addHour()->getTimestamp(),
            $day->addDays($this->days() + 1)->getTimestamp(),
            self::TOP_KEEP,
            ...array_values($tops),
        ]];
    }

    protected function statsKey(CarbonImmutable $hour): string
    {
        return 'fail2ban:stats:'.$hour->format('YmdH');
    }

    protected function topKey(string $category, CarbonImmutable $day): string
    {
        return 'fail2ban:top:'.$category.':'.$day->format('Ymd');
    }

    protected function days(): int
    {
        return max(1, (int) config('fail2ban.stats_days', 30));
    }
}
