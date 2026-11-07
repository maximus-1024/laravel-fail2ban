<?php

namespace Maximus\Fail2Ban\Repositories;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Redis\Factory as RedisFactory;
use Illuminate\Validation\ValidationException;
use InvalidArgumentException;
use Maximus\Fail2Ban\Contracts\AllowlistRepository;
use Maximus\Fail2Ban\Repositories\Concerns\InteractsWithRedis;
use Maximus\Fail2Ban\Visitor;

class RedisAllowlistRepository implements AllowlistRepository
{
    use InteractsWithRedis;

    /**
     * 面板条目的哈希：字段是条目，值是 JSON {note, added_by, added_at}。
     */
    public const KEY = 'fail2ban:allow';

    /**
     * 内置段的中文标签。
     */
    public const LABELS = [
        'private' => '内网段',
        'loopback' => '回环',
        'cloudflare' => 'Cloudflare',
        'extra' => '配置文件',
    ];

    /**
     * Create a new repository instance.
     */
    public function __construct(RedisFactory $redis)
    {
        $this->redis = $redis;
    }

    public function match(string $ip): ?array
    {
        // ::ffff:a.b.c.d 按 IPv4 匹配；其余 IPv6 用原地址，不收窄到 /64，单地址条目才能命中。
        try {
            $address = Visitor::ip($ip);
        } catch (InvalidArgumentException) {
            return null;
        }

        foreach ($this->builtin() as $entry) {
            if (Visitor::covers($entry['entry'], $address)) {
                return ['entry' => $entry['entry'], 'source' => $entry['source']];
            }
        }

        foreach ($this->connection()->hkeys(self::KEY) ?: [] as $entry) {
            if (Visitor::covers($entry, $address)) {
                return ['entry' => $entry, 'source' => 'panel'];
            }
        }

        return null;
    }

    public function builtin(): array
    {
        $groups = (array) config('fail2ban.allowlist.builtin', []);
        $groups['extra'] = (array) config('fail2ban.allowlist.extra', []);

        $entries = [];

        foreach ($groups as $source => $list) {
            foreach ((array) $list as $entry) {
                $entries[] = [
                    'entry' => (string) $entry,
                    'label' => self::LABELS[$source] ?? (string) $source,
                    'source' => (string) $source,
                ];
            }
        }

        return $entries;
    }

    public function entries(): array
    {
        $entries = [];

        foreach ($this->connection()->hgetall(self::KEY) ?: [] as $entry => $json) {
            $data = json_decode($json, true) ?: [];

            $entries[] = [
                'entry' => (string) $entry,
                'note' => $data['note'] ?? null,
                'added_by' => (string) ($data['added_by'] ?? ''),
                'added_at' => (int) ($data['added_at'] ?? 0),
            ];
        }

        usort($entries, fn ($a, $b) => [$a['added_at'], $a['entry']] <=> [$b['added_at'], $b['entry']]);

        return $entries;
    }

    public function add(string $entry, ?string $note, string $actor): array
    {
        $normalized = static::normalize($entry);

        if ($normalized === null) {
            throw ValidationException::withMessages(['entry' => ['不是合法的 IP 或 CIDR。']]);
        }

        $record = [
            'entry' => $normalized,
            'note' => $note === null || trim($note) === '' ? null : $note,
            'added_by' => $actor,
            'added_at' => CarbonImmutable::now()->getTimestamp(),
        ];

        $this->connection()->hset(self::KEY, $normalized, $this->encode(
            ['note' => $record['note'], 'added_by' => $actor, 'added_at' => $record['added_at']]
        ));

        return $record;
    }

    public function remove(string $entry): bool
    {
        $normalized = static::normalize($entry);

        return $normalized !== null && (int) $this->connection()->hdel(self::KEY, $normalized) > 0;
    }

    /**
     * 规范化一个 IP 或 CIDR 条目；不合法时返回 null。
     *
     * IPv6 写成压缩形式；不带前缀长度的就是单个地址。
     */
    public static function normalize(string $entry): ?string
    {
        $entry = trim($entry);
        $parts = explode('/', $entry, 2);

        if (filter_var($parts[0], FILTER_VALIDATE_IP) === false) {
            return null;
        }

        $ip = inet_ntop(inet_pton($parts[0]));
        $bits = str_contains($ip, ':') ? 128 : 32;

        if (! isset($parts[1])) {
            return $ip;
        }

        if (! preg_match('/^\d{1,3}$/', $parts[1]) || (int) $parts[1] > $bits) {
            return null;
        }

        return $ip.'/'.(int) $parts[1];
    }
}
