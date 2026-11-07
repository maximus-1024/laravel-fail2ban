<?php

namespace Maximus\Fail2Ban\Tests\Feature\Storage;

use Maximus\Fail2Ban\Contracts\BanRepository;
use Maximus\Fail2Ban\Contracts\SettingsRepository;
use Maximus\Fail2Ban\Tests\Support\InteractsWithFail2BanRedis;
use Maximus\Fail2Ban\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;

class BanRepositoryTest extends TestCase
{
    use InteractsWithFail2BanRedis;

    private const V = '203.0.113.47';

    private const REPEAT = ['enabled' => true, 'factor' => 2, 'max_days' => 7, 'keep_days' => 7];

    private const INFO_FIELDS = [
        'source', 'incident', 'rule', 'count', 'offense', 'ip', 'region', 'user_agent', 'observe',
        'banned_at', 'unban_at', 'ban_minutes', 'blocked', 'last_blocked_at', 'operator', 'note',
        'requests', 'other_rules',
    ];

    private BanRepository $bans;

    protected function setUp(): void
    {
        parent::setUp();

        $this->bans = $this->app->make(BanRepository::class);
    }

    private function hit(string $rule, ?string $dedupe, string $path = '/x', int $window = 5, int $max = 100, string $visitor = self::V, int $time = 1762400000): array
    {
        return $this->recordHit($rule, $visitor, $dedupe, ['method' => 'GET', 'path' => $path, 'time' => $time], $window, $max);
    }

    private function autoBan(string $incident = 'BAN-20261107-AAAAAA', array $repeat = self::REPEAT, int $ruleBan = 30, string $rule = 'not-found-scan', string $visitor = self::V): ?array
    {
        return $this->bans->ban($visitor, [
            'incident' => $incident,
            'rule' => $rule,
            'ip' => self::V,
            'region' => '荷兰',
            'user_agent' => 'sqlmap/1.7',
        ], $ruleBan, $repeat);
    }

    private function expireBan(string $visitor = self::V): void
    {
        $this->expireNow('fail2ban:ban:'.$visitor, 'fail2ban:info:'.$visitor);
    }


    #[Test]
    public function the_same_dedupe_key_is_counted_once(): void
    {
        $this->assertSame(['count' => 1, 'added' => true], $this->hit('not-found-scan', '/a'));
        $this->assertSame(['count' => 1, 'added' => false], $this->hit('not-found-scan', '/a'));
        $this->assertSame(['count' => 1, 'added' => false], $this->hit('not-found-scan', '/a'));
        $this->assertSame(['count' => 2, 'added' => true], $this->hit('not-found-scan', '/b'));

        $this->assertSame(2, $this->redis()->hlen('fail2ban:hits:not-found-scan:'.self::V));
    }

    #[Test]
    public function a_null_dedupe_key_counts_every_request(): void
    {
        foreach ([1, 2, 3, 4] as $expected) {
            $this->assertSame(['count' => $expected, 'added' => true], $this->hit('scanner-agent', null));
        }

        $this->assertSame(4, $this->redis()->hlen('fail2ban:hits:scanner-agent:'.self::V));
    }

    #[Test]
    public function rules_count_independently(): void
    {
        $this->hit('not-found-scan', '/a');
        $this->hit('not-found-scan', '/b');

        $this->assertSame(['count' => 1, 'added' => true], $this->hit('sensitive-path', '/a'));
        $this->assertSame(['count' => 1, 'added' => true], $this->hit('not-found-scan', '/a', visitor: '198.51.100.1'));
        $this->assertSame(2, $this->redis()->hlen('fail2ban:hits:not-found-scan:'.self::V));
    }


    #[Test]
    public function the_hits_key_expires_from_the_first_hit(): void
    {
        $key = 'fail2ban:hits:not-found-scan:'.self::V;

        $this->hit('not-found-scan', '/a', window: 5);
        $ttl = $this->redis()->ttl($key);
        $this->assertGreaterThan(295, $ttl);
        $this->assertLessThanOrEqual(300, $ttl);

        // 后续命中不续期：从第一次命中算起
        $this->redis()->expire($key, 50);
        $this->hit('not-found-scan', '/b', window: 5);
        $this->assertLessThanOrEqual(50, $this->redis()->ttl($key));
    }

    #[Test]
    public function a_missing_ttl_is_restored_on_the_next_hit(): void
    {
        $key = 'fail2ban:hits:not-found-scan:'.self::V;

        $this->hit('not-found-scan', '/a', window: 5);
        $this->redis()->persist($key);
        $this->assertSame(-1, $this->redis()->ttl($key));

        // 去重命中（什么都不新增）也要补上过期时间
        $this->hit('not-found-scan', '/a', window: 5);
        $this->assertGreaterThan(0, $this->redis()->ttl($key));
    }

    #[Test]
    public function hits_stop_at_hits_max_and_keep_their_ttl(): void
    {
        $key = 'fail2ban:hits:not-found-scan:'.self::V;
        $counts = [];

        for ($i = 1; $i <= 8; $i++) {
            $counts[] = $this->hit('not-found-scan', "/p{$i}", max: 5);
        }

        $this->assertSame([1, 2, 3, 4, 5, 5, 5, 5], array_column($counts, 'count'));
        $this->assertSame([true, true, true, true, true, false, false, false], array_column($counts, 'added'));
        $this->assertSame(5, $this->redis()->hlen($key));

        $this->redis()->persist($key);
        $this->hit('scanner-agent', null, max: 5);
        $this->hit('not-found-scan', '/p9', max: 5);
        $this->assertGreaterThan(0, $this->redis()->ttl($key));
        $this->assertSame(5, $this->redis()->hlen($key));
    }

    #[Test]
    public function hit_records_keep_only_time_method_and_path(): void
    {
        $this->recordHit('attack-pattern', self::V, '/q', [
            'method' => 'GET',
            'path' => '/q?x=1',
            'time' => 1762400000,
            'body' => 'password=secret',
            'cookie' => 'session=abc',
            'headers' => ['authorization' => 'Bearer x'],
        ], 1);

        $this->assertSame(['attack-pattern' => [[
            'time' => 1762400000, 'method' => 'GET', 'path' => '/q?x=1',
        ]]], $this->bans->hits(self::V));

        $raw = $this->redis()->hgetall('fail2ban:hits:attack-pattern:'.self::V);
        $this->assertStringNotContainsString('secret', implode('', $raw));
        $this->assertStringNotContainsString('session', implode('', $raw));
    }

    // ---------------------------------------------------------------- 前缀

    #[Test]
    public function lua_scripts_and_plain_commands_see_the_same_prefixed_keys(): void
    {
        $this->hit('not-found-scan', '/a');

        $this->assertSame(1, $this->redis()->hlen('fail2ban:hits:not-found-scan:'.self::V));
        $this->assertTrue($this->existsRaw('f2btest:fail2ban:hits:not-found-scan:'.self::V));
        $this->assertFalse($this->existsRaw('fail2ban:hits:not-found-scan:'.self::V));

        $this->autoBan();

        foreach (['ban:'.self::V, 'info:'.self::V, 'bans', 'repeat:'.self::V] as $key) {
            $this->assertTrue($this->existsRaw('f2btest:fail2ban:'.$key), $key);
            $this->assertFalse($this->existsRaw('fail2ban:'.$key), $key);
        }

        $this->assertSame('BAN-20261107-AAAAAA', explode('|', $this->redis()->get('fail2ban:ban:'.self::V))[0]);
        $this->assertFalse($this->existsRaw('f2btest:fail2ban:hits:not-found-scan:'.self::V));
    }


    #[Test]
    public function an_auto_ban_records_complete_attacker_information(): void
    {
        $this->hit('not-found-scan', '/c', '/c', time: 1762400030);
        $this->hit('not-found-scan', '/a', '/a', time: 1762400010);
        $this->hit('not-found-scan', '/b', '/b', time: 1762400020);
        $this->hit('sensitive-path', '/.env', '/.env');
        $this->hit('scanner-agent', null);
        $this->hit('scanner-agent', null);

        $before = time();
        $ban = $this->autoBan();
        $after = time();

        $this->assertSame(self::V, $ban['visitor']);
        $this->assertSame('BAN-20261107-AAAAAA', $ban['incident']);
        $this->assertSame('auto', $ban['source']);
        $this->assertSame('not-found-scan', $ban['rule']);
        $this->assertSame(3, $ban['count']);
        $this->assertSame(1, $ban['offense']);
        $this->assertSame(self::V, $ban['ip']);
        $this->assertSame('荷兰', $ban['region']);
        $this->assertSame('sqlmap/1.7', $ban['user_agent']);
        $this->assertFalse($ban['observe']);
        $this->assertGreaterThanOrEqual($before, $ban['banned_at']);
        $this->assertLessThanOrEqual($after, $ban['banned_at']);
        $this->assertSame($ban['banned_at'] + 1800, $ban['unban_at']);
        $this->assertSame(30, $ban['ban_minutes']);
        $this->assertSame(0, $ban['blocked']);
        $this->assertNull($ban['last_blocked_at']);
        $this->assertSame(1762400010, $ban['first_hit_at']);
        $this->assertSame(['sensitive-path' => 1, 'scanner-agent' => 2], $ban['other_rules']);
        $this->assertSame(['/a', '/b', '/c'], array_column($ban['requests'], 'path'));
        $this->assertNull($ban['operator']);

        $this->assertEquals($ban, $this->bans->find(self::V));

        // 封禁键、攻击者信息同过期；索引按解封时间；命中记录全部清空
        $this->assertEqualsWithDelta(1800, $this->redis()->ttl('fail2ban:ban:'.self::V), 2);
        $this->assertEqualsWithDelta(1800, $this->redis()->ttl('fail2ban:info:'.self::V), 2);
        $this->assertEquals($ban['unban_at'], $this->redis()->zscore('fail2ban:bans', self::V));
        $this->assertSame([], $this->bans->hits(self::V));

        // 只有约定的字段，没有正文、Cookie、凭据
        $this->assertSame([], array_diff(array_keys($this->redis()->hgetall('fail2ban:info:'.self::V)), self::INFO_FIELDS));
    }

    #[Test]
    public function each_block_increments_the_blocked_count(): void
    {
        $this->autoBan();

        $this->assertSame(1, $this->bans->recordBlock(self::V));
        $this->assertSame(2, $this->bans->recordBlock(self::V));
        $this->assertSame(3, $this->bans->recordBlock(self::V));

        $ban = $this->bans->find(self::V);
        $this->assertSame(3, $ban['blocked']);
        $this->assertEqualsWithDelta(time(), $ban['last_blocked_at'], 2);

        // 被拦不续期，也不会让攻击者信息失去过期时间
        $this->assertGreaterThan(0, $this->redis()->ttl('fail2ban:info:'.self::V));
        $this->assertLessThanOrEqual(1800, $this->redis()->ttl('fail2ban:ban:'.self::V));
    }

    #[Test]
    public function recording_a_block_without_a_ban_writes_nothing(): void
    {
        $this->assertNull($this->bans->recordBlock(self::V));
        $this->assertSame(0, $this->redis()->exists('fail2ban:info:'.self::V));
    }

    // ---------------------------------------------------------------- 不覆盖

    #[Test]
    public function an_existing_ban_is_never_overwritten_by_an_auto_ban(): void
    {
        $this->autoBan('BAN-20261107-FIRST1');
        $this->redis()->expire('fail2ban:ban:'.self::V, 1000);
        $this->redis()->expire('fail2ban:info:'.self::V, 1000);

        $value = $this->redis()->get('fail2ban:ban:'.self::V);
        $info = $this->redis()->hgetall('fail2ban:info:'.self::V);
        $this->hit('sensitive-path', '/.git/config');

        $this->assertNull($this->autoBan('BAN-20261107-SECOND', ruleBan: 120, rule: 'sensitive-path'));

        $this->assertSame($value, $this->redis()->get('fail2ban:ban:'.self::V));
        $this->assertSame($info, $this->redis()->hgetall('fail2ban:info:'.self::V));
        $this->assertLessThanOrEqual(1000, $this->redis()->ttl('fail2ban:ban:'.self::V));
        $this->assertLessThanOrEqual(1000, $this->redis()->ttl('fail2ban:info:'.self::V));
        $this->assertSame('1', $this->redis()->get('fail2ban:repeat:'.self::V));
        $this->assertSame(1, $this->redis()->hlen('fail2ban:hits:sensitive-path:'.self::V));
    }

    #[Test]
    public function a_manual_ban_is_not_overwritten_by_an_auto_ban(): void
    {
        $this->bans->banManually(self::V, ['incident' => 'BAN-20261107-MANUAL', 'operator' => 'admin'], 60);

        $this->assertNull($this->autoBan());
        $this->assertSame('manual', $this->bans->find(self::V)['source']);
        $this->assertSame(0, $this->redis()->exists('fail2ban:repeat:'.self::V));
    }


    #[Test]
    public function repeat_offenders_get_longer_bans_within_repeat_keep(): void
    {
        $minutes = [];
        $offenses = [];

        for ($i = 0; $i < 4; $i++) {
            $ban = $this->autoBan("BAN-20261107-AAAAA{$i}");
            $minutes[] = $ban['ban_minutes'];
            $offenses[] = $ban['offense'];

            $this->assertEqualsWithDelta($ban['ban_minutes'] * 60, $this->redis()->ttl('fail2ban:ban:'.self::V), 2);
            $this->assertEqualsWithDelta($ban['ban_minutes'] * 60 + 7 * 86400, $this->redis()->ttl('fail2ban:repeat:'.self::V), 2);

            $this->expireBan();
        }

        $this->assertSame([30, 60, 120, 240], $minutes);
        $this->assertSame([1, 2, 3, 4], $offenses);
    }

    #[Test]
    public function repeat_bans_are_capped_at_repeat_max(): void
    {
        $repeat = ['max_days' => 1] + self::REPEAT;
        $minutes = [];

        for ($i = 0; $i < 8; $i++) {
            $minutes[] = $this->autoBan(repeat: $repeat)['ban_minutes'];
            $this->expireBan();
        }

        $this->assertSame([30, 60, 120, 240, 480, 960, 1440, 1440], $minutes);
        $this->assertSame(20000, $this->autoBan(repeat: $repeat, ruleBan: 20000)['ban_minutes']);
    }

    #[Test]
    public function the_count_starts_over_after_repeat_keep(): void
    {
        $this->autoBan();
        $this->expireBan();
        $this->expireNow('fail2ban:repeat:'.self::V);

        $ban = $this->autoBan();

        $this->assertSame(30, $ban['ban_minutes']);
        $this->assertSame(1, $ban['offense']);
    }

    #[Test]
    public function disabled_repeat_always_uses_the_rule_ban(): void
    {
        $repeat = ['enabled' => false] + self::REPEAT;

        $this->assertSame(30, $this->autoBan(repeat: $repeat)['ban_minutes']);
        $this->expireBan();
        $this->assertSame(30, $this->autoBan(repeat: $repeat)['ban_minutes']);
    }

    #[Test]
    public function manual_bans_are_not_lengthened_and_not_counted(): void
    {
        $this->autoBan();
        $this->expireBan();

        $manual = $this->bans->banManually(self::V, ['incident' => 'BAN-20261107-MANUAL', 'operator' => 'admin'], 45);

        $this->assertSame(45, $manual['ban_minutes']);
        $this->assertNull($manual['offense']);
        $this->assertEqualsWithDelta(2700, $this->redis()->ttl('fail2ban:ban:'.self::V), 2);
        $this->assertSame('1', $this->redis()->get('fail2ban:repeat:'.self::V));

        $this->expireBan();

        $this->assertSame(60, $this->autoBan()['ban_minutes']);
    }

    #[Test]
    public function unban_clears_the_repeat_record(): void
    {
        $this->autoBan();
        $this->bans->unban(self::V);

        $this->assertSame(0, $this->redis()->exists('fail2ban:repeat:'.self::V));
        $this->assertSame(30, $this->autoBan()['ban_minutes']);
    }

    // ---------------------------------------------------------------- 手动封禁

    #[Test]
    public function a_manual_ban_replaces_the_existing_ban(): void
    {
        $this->hit('not-found-scan', '/a');
        $this->autoBan();
        $this->bans->recordBlock(self::V);

        $first = $this->bans->banManually(self::V, ['incident' => 'BAN-20261107-MANUA1', 'operator' => 'alice', 'note' => '先封'], 10);
        $ban = $this->bans->banManually(self::V, ['incident' => 'BAN-20261107-MANUA2', 'operator' => 'bob', 'note' => '以这次为准', 'ip' => self::V], 20);

        $this->assertSame('BAN-20261107-MANUA1', $first['incident']);
        $this->assertEquals($ban, $this->bans->find(self::V));
        $this->assertSame('manual', $ban['source']);
        $this->assertSame('BAN-20261107-MANUA2', $ban['incident']);
        $this->assertSame('bob', $ban['operator']);
        $this->assertSame('以这次为准', $ban['note']);
        $this->assertSame(20, $ban['ban_minutes']);
        $this->assertNull($ban['rule']);
        $this->assertNull($ban['count']);
        $this->assertSame(0, $ban['blocked']);
        $this->assertSame([], $ban['requests']);
        $this->assertSame($ban['banned_at'] + 1200, $ban['unban_at']);
        $this->assertEqualsWithDelta(1200, $this->redis()->ttl('fail2ban:ban:'.self::V), 2);
        $this->assertEqualsWithDelta(1200, $this->redis()->ttl('fail2ban:info:'.self::V), 2);
        $this->assertEquals($ban['unban_at'], $this->redis()->zscore('fail2ban:bans', self::V));
    }

    // ---------------------------------------------------------------- 解封

    #[Test]
    public function unban_removes_every_trace_of_the_visitor(): void
    {
        $this->autoBan();
        $this->hit('not-found-scan', '/again');
        $this->hit('scanner-agent', null);

        $removed = $this->bans->unban(self::V);

        $this->assertSame('BAN-20261107-AAAAAA', $removed['incident']);
        $this->assertNull($this->bans->find(self::V));
        $this->assertSame([], $this->bans->hits(self::V));

        foreach (['ban:', 'info:', 'repeat:', 'hits:not-found-scan:', 'hits:scanner-agent:'] as $key) {
            $this->assertSame(0, $this->redis()->exists('fail2ban:'.$key.self::V), $key);
        }

        $this->assertFalse($this->redis()->zscore('fail2ban:bans', self::V));
        $this->assertNull($this->bans->unban(self::V));
    }

    // ---------------------------------------------------------------- 名单

    #[Test]
    public function all_lists_active_bans_by_unban_time_and_prunes_the_index(): void
    {
        $this->autoBan('BAN-20261107-LONG01', ruleBan: 120, visitor: '198.51.100.1');
        $this->autoBan('BAN-20261107-SHORT1', ruleBan: 30, visitor: '198.51.100.2');
        $this->bans->banManually('2001:db8::/64', ['incident' => 'BAN-20261107-MID001', 'operator' => 'admin'], 60);

        $this->redis()->zadd('fail2ban:bans', time() - 10, 'expired-entry');
        $this->redis()->zadd('fail2ban:bans', time() + 999, 'ban-key-gone');

        $this->assertSame(['198.51.100.2', '2001:db8::/64', '198.51.100.1'], array_column($this->bans->all(), 'visitor'));

        // 只按分数清理：已到期的成员被删；封禁键不在、分数未到的成员只是不列出，留到它的分数到期
        $this->assertSame(['ban-key-gone', '198.51.100.2', '2001:db8::/64', '198.51.100.1'], $this->redis()->zrange('fail2ban:bans', 0, -1));

        $this->expireBan('198.51.100.2');
        $this->assertSame(['2001:db8::/64', '198.51.100.1'], array_column($this->bans->all(), 'visitor'));
    }

    // ---------------------------------------------------------------- 进入路径

    #[Test]
    public function lookup_returns_the_ban_and_the_settings_together(): void
    {
        $result = $this->bans->lookup(self::V);

        $this->assertNull($result['ban']);
        $this->assertEquals($this->app->make(SettingsRepository::class)->defaults(), $result['settings']);

        $this->app->make(SettingsRepository::class)->save(['mode' => 'block'], 'admin');
        $ban = $this->autoBan();

        $result = $this->bans->lookup(self::V);

        $this->assertSame(['incident' => 'BAN-20261107-AAAAAA', 'banned_at' => $ban['banned_at']], $result['ban']);
        $this->assertSame('block', $result['settings']['mode']);
        $this->assertSame('admin', $result['settings']['updated_by']);
    }
}
