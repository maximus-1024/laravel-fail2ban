<?php

namespace Maximus\Fail2Ban\Repositories;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Redis\Factory as RedisFactory;
use InvalidArgumentException;
use Maximus\Fail2Ban\BanDuration;
use Maximus\Fail2Ban\Contracts\BanRepository;
use Maximus\Fail2Ban\Contracts\SettingsRepository;
use Maximus\Fail2Ban\LuaScripts;
use Maximus\Fail2Ban\Repositories\Concerns\FiltersRecords;
use Maximus\Fail2Ban\Repositories\Concerns\InteractsWithRedis;
use Maximus\Fail2Ban\Support\Text;
use RuntimeException;

class RedisBanRepository implements BanRepository
{
    use FiltersRecords, InteractsWithRedis;

    /**
     * The settings repository (用于把设置并进 lookup() 的同一个管道).
     *
     * @var \Maximus\Fail2Ban\Contracts\SettingsRepository
     */
    public $settings;

    /**
     * The stats repository (用于把命中统计并进 recordHits() 的同一个管道，所以是 Redis 实现本身).
     *
     * @var \Maximus\Fail2Ban\Repositories\RedisStatsRepository
     */
    public $stats;

    /**
     * Create a new repository instance.
     */
    public function __construct(RedisFactory $redis, SettingsRepository $settings, RedisStatsRepository $stats)
    {
        $this->redis = $redis;
        $this->settings = $settings;
        $this->stats = $stats;
    }

    public function lookup(string $visitor): array
    {
        [$ban, $stored] = $this->pipeline(function ($pipe) use ($visitor) {
            $pipe->get($this->banKey($visitor));
            $pipe->hgetall(RedisSettingsRepository::KEY);
        });

        if (is_string($ban) && $ban !== '') {
            [$incident, $bannedAt] = $this->parseBanValue($ban);

            $ban = ['incident' => $incident, 'banned_at' => $bannedAt];
        } else {
            $ban = null;
        }

        return [
            'ban' => $ban,
            'settings' => $this->settings->resolve(is_array($stored) ? $stored : []),
        ];
    }

    public function recordHits(string $visitor, array $hits, int $max, ?string $target = null, ?string $region = null): array
    {
        if (($hits = array_values($hits)) === []) {
            return [];
        }

        // 每条命中两个脚本：记命中、命中统计。
        $results = $this->pipeline(function ($pipe) use ($visitor, $hits, $max, $target, $region) {
            foreach ($hits as $hit) {
                $this->queueScript($pipe, ...$this->recordHitCommand($hit['rule'], $visitor, $hit['dedupe'], $hit['record'], $hit['window'], $max));
                $this->queueScript($pipe, ...$this->stats->incrementHitCommand($hit['rule'], $visitor, $target, $region));
            }
        });

        return array_map(fn (int $i) => $this->hitResult($results[$i * 2] ?? null), array_keys($hits));
    }

    /**
     * 记一次命中的脚本调用 [脚本, KEYS, ARGV]。记录只存时间、方法、地址三项（请求正文、Cookie、凭据无从进入）。
     *
     * @return array{0: string, 1: list<string>, 2: list<string|int>}
     */
    protected function recordHitCommand(string $rule, string $visitor, ?string $dedupe, array $record, int $windowMinutes, int $max): array
    {
        return [LuaScripts::recordHit(), [$this->hitsKey($rule, $visitor)], [
            $dedupe === null ? '' : 'k:'.$dedupe,
            $this->encode(['time' => (int) $record['time'], 'method' => $record['method'], 'path' => $record['path']]),
            max(1, $windowMinutes) * 60,
            max(1, $max),
        ]];
    }

    /**
     * 记命中脚本的返回值 {条数, 是否新增}。
     *
     * @return array{count: int, added: bool}
     */
    protected function hitResult(mixed $result): array
    {
        if (! is_array($result) || count($result) < 2) {
            throw new RuntimeException('Fail2Ban could not record the rule hit.');
        }

        return ['count' => (int) $result[0], 'added' => (bool) $result[1]];
    }

    public function hits(string $visitor): array
    {
        $rules = $this->rules();

        $results = $this->pipeline(function ($pipe) use ($rules, $visitor) {
            foreach ($rules as $rule) {
                $pipe->hvals($this->hitsKey($rule, $visitor));
            }
        });

        $hits = [];

        foreach ($rules as $i => $rule) {
            if (! empty($results[$i])) {
                $hits[$rule] = $this->sortRequests(array_map(
                    fn ($json) => json_decode($json, true), $results[$i]
                ));
            }
        }

        return $hits;
    }

    public function ban(string $visitor, array $details, int $ruleBan, array $repeat): ?array
    {
        $rule = $details['rule'] ?? throw new InvalidArgumentException('The [rule] detail is required.');
        $incident = $details['incident'] ?? throw new InvalidArgumentException('The [incident] detail is required.');

        $schedule = BanDuration::schedule($ruleBan, $repeat);
        $others = array_values(array_diff($this->rules(), [$rule]));

        $info = $this->infoFields([
            'source' => 'auto',
            'rule' => $rule,
            'ip' => $details['ip'] ?? null,
            'region' => $details['region'] ?? null,
            'user_agent' => $details['user_agent'] ?? null,
            'observe' => $details['observe'] ?? false,
        ]);

        $info = $this->script(LuaScripts::ban(), [
            $this->banKey($visitor),
            $this->infoKey($visitor),
            $this->indexKey(),
            $this->repeatKey($visitor),
            $this->hitsKey($rule, $visitor),
            ...array_map(fn ($other) => $this->hitsKey($other, $visitor), $others),
        ], [
            $incident,
            CarbonImmutable::now()->getTimestamp(),
            $visitor,
            max(1, (int) ($repeat['keep_days'] ?? 1)) * 86400,
            empty($details['observe']) ? 1 : 0,
            count($schedule),
            ...$schedule,
            count($others),
            ...$others,
            ...$this->pairs($info),
        ]);

        if (! is_array($info)) {
            return null;
        }

        $info = $this->unflatten($info);

        return $this->present($visitor, $this->banValue($info['incident'], (int) $info['banned_at']), $info);
    }

    public function banManually(string $visitor, array $details, int $minutes): array
    {
        $incident = $details['incident'] ?? throw new InvalidArgumentException('The [incident] detail is required.');
        $operator = $details['operator'] ?? throw new InvalidArgumentException('The [operator] detail is required.');

        if ($minutes < 1) {
            throw new InvalidArgumentException('The ban duration must be at least one minute.');
        }

        $now = CarbonImmutable::now()->getTimestamp();
        $seconds = $minutes * 60;
        $unbanAt = $now + $seconds;

        $info = $this->infoFields([
            'source' => 'manual',
            'incident' => $incident,
            'operator' => $operator,
            'note' => $details['note'] ?? null,
            'ip' => $details['ip'] ?? null,
            'region' => $details['region'] ?? null,
            'user_agent' => $details['user_agent'] ?? null,
            'observe' => $details['observe'] ?? false,
            'banned_at' => $now,
            'unban_at' => $unbanAt,
            'ban_minutes' => $minutes,
            'blocked' => 0,
        ]);

        $this->script(LuaScripts::banManually(), [
            $this->banKey($visitor),
            $this->infoKey($visitor),
            $this->indexKey(),
        ], [
            $this->banValue($incident, $now),
            $seconds,
            $unbanAt,
            $visitor,
            ...$this->pairs($info),
        ]);

        return $this->present($visitor, $this->banValue($incident, $now), $info);
    }

    public function unban(string $visitor): ?array
    {
        [$ban, $info] = $this->script(LuaScripts::unban(), [
            $this->banKey($visitor),
            $this->infoKey($visitor),
            $this->indexKey(),
            $this->repeatKey($visitor),
            ...array_map(fn ($rule) => $this->hitsKey($rule, $visitor), $this->rules()),
        ], [$visitor]);

        return is_string($ban) && $ban !== ''
            ? $this->present($visitor, $ban, $this->unflatten((array) $info))
            : null;
    }

    public function recordBlock(string $visitor): ?int
    {
        $blocked = $this->script(LuaScripts::recordBlock(), [$this->infoKey($visitor)], [
            CarbonImmutable::now()->getTimestamp(),
        ]);

        return $blocked === false || $blocked === null ? null : (int) $blocked;
    }

    public function find(string $visitor): ?array
    {
        [$ban, $info] = $this->pipeline(function ($pipe) use ($visitor) {
            $pipe->get($this->banKey($visitor));
            $pipe->hgetall($this->infoKey($visitor));
        });

        if (! is_string($ban) || $ban === '') {
            return null;
        }

        return $this->present($visitor, $ban, is_array($info) ? $info : []);
    }

    public function all(array $filters = []): array
    {
        [, $visitors] = $this->pipeline(function ($pipe) {
            $pipe->zremrangebyscore($this->indexKey(), '-inf', CarbonImmutable::now()->getTimestamp());
            $pipe->zrange($this->indexKey(), 0, -1);
        });

        if (! is_array($visitors) || $visitors === []) {
            return [];
        }

        // 索引只按分数（解封时间）清理，上面那一步就是。封禁键不在了的成员只是不列出，不在这里删：
        // 从读到删之间可能有请求刚封了它（ban() 会更新它的分数），按「读的时候不在」去删会误删新索引项。
        // 这样的成员到它的解封时间就被上面清掉。

        $results = $this->pipeline(function ($pipe) use ($visitors) {
            foreach ($visitors as $visitor) {
                $pipe->get($this->banKey($visitor));
                $pipe->hgetall($this->infoKey($visitor));
            }
        });

        $bans = [];

        foreach ($visitors as $i => $visitor) {
            $ban = $results[$i * 2];

            if (is_string($ban) && $ban !== '') {
                $bans[] = $this->present($visitor, $ban, is_array($results[$i * 2 + 1]) ? $results[$i * 2 + 1] : []);
            }
        }

        usort($bans, fn ($a, $b) => $a['unban_at'] <=> $b['unban_at']);

        return $this->filterRecords($bans, $filters, ['visitor', 'ip', 'incident']);
    }

    /**
     * 把封禁键内容与攻击者信息哈希拼成封禁记录。
     */
    protected function present(string $visitor, string $ban, array $info): array
    {
        [$incident, $bannedAt] = $this->parseBanValue($ban);

        $int = fn (string $field) => isset($info[$field]) && $info[$field] !== '' ? (int) $info[$field] : null;
        $str = fn (string $field) => isset($info[$field]) && $info[$field] !== '' ? (string) $info[$field] : null;

        $requests = isset($info['requests']) ? (array) json_decode($info['requests'], true) : [];
        $requests = $this->sortRequests($requests);

        $otherRules = isset($info['other_rules']) ? json_decode($info['other_rules'], true) : [];

        return [
            'visitor' => $visitor,
            'incident' => $str('incident') ?? $incident,
            'source' => $str('source') ?? 'auto',
            'rule' => $str('rule'),
            'count' => $int('count'),
            'offense' => $int('offense'),
            'ip' => $str('ip'),
            'region' => $str('region'),
            'user_agent' => $str('user_agent'),
            'observe' => ($info['observe'] ?? '0') === '1',
            'banned_at' => $int('banned_at') ?? $bannedAt,
            'unban_at' => $int('unban_at') ?? $bannedAt,
            'ban_minutes' => $int('ban_minutes'),
            'blocked' => $int('blocked') ?? 0,
            'last_blocked_at' => $int('last_blocked_at'),
            'operator' => $str('operator'),
            'note' => $str('note'),
            'first_hit_at' => $requests === [] ? null : $requests[0]['time'],
            'other_rules' => is_array($otherRules) ? array_map('intval', $otherRules) : [],
            'requests' => $requests,
        ];
    }

    /**
     * 攻击者信息哈希的字段：去掉 null，布尔写成 1/0，浏览器标识截断（Text::userAgent()）。
     *
     * 只写调用方列出的字段——请求正文、Cookie、凭据无从进入。
     *
     * @return array<string, string>
     */
    protected function infoFields(array $info): array
    {
        if (array_key_exists('user_agent', $info)) {
            $info['user_agent'] = Text::userAgent($info['user_agent']);
        }

        $fields = [];

        foreach ($info as $field => $value) {
            if ($value === null) {
                continue;
            }

            $fields[$field] = is_bool($value) ? ($value ? '1' : '0') : (string) $value;
        }

        return $fields;
    }

    /**
     * 哈希字段展开成「字段, 值, 字段, 值…」，传给脚本。
     *
     * @param  array<string, string>  $fields
     * @return list<string>
     */
    protected function pairs(array $fields): array
    {
        $pairs = [];

        foreach ($fields as $field => $value) {
            array_push($pairs, (string) $field, $value);
        }

        return $pairs;
    }

    /**
     * 脚本返回的 HGETALL 扁平列表还原成关联数组。
     *
     * @return array<string, string>
     */
    protected function unflatten(array $list): array
    {
        $fields = [];

        for ($i = 0; $i + 1 < count($list); $i += 2) {
            $fields[(string) $list[$i]] = (string) $list[$i + 1];
        }

        return $fields;
    }

    /**
     * @param  list<array|null>  $requests
     */
    protected function sortRequests(array $requests): array
    {
        $requests = array_values(array_filter($requests, 'is_array'));

        usort($requests, fn ($a, $b) => ($a['time'] ?? 0) <=> ($b['time'] ?? 0));

        return $requests;
    }

    /**
     * 封禁键的内容：「事件编号|封禁时间」，纯文本。
     */
    protected function banValue(string $incident, int $bannedAt): string
    {
        return $incident.'|'.$bannedAt;
    }

    /**
     * @return array{0: string, 1: int}
     */
    protected function parseBanValue(string $value): array
    {
        [$incident, $bannedAt] = array_pad(explode('|', $value, 2), 2, null);

        return [$incident, (int) $bannedAt];
    }

    /**
     * 配置里的规则标识。
     *
     * @return list<string>
     */
    protected function rules(): array
    {
        return array_keys((array) config('fail2ban.rules'));
    }

    protected function banKey(string $visitor): string
    {
        return 'fail2ban:ban:'.$visitor;
    }

    protected function infoKey(string $visitor): string
    {
        return 'fail2ban:info:'.$visitor;
    }

    protected function indexKey(): string
    {
        return 'fail2ban:bans';
    }

    protected function repeatKey(string $visitor): string
    {
        return 'fail2ban:repeat:'.$visitor;
    }

    protected function hitsKey(string $rule, string $visitor): string
    {
        return 'fail2ban:hits:'.$rule.':'.$visitor;
    }
}
