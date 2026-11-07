<?php

namespace Maximus\Fail2Ban\Tests\Feature\Storage;

use Illuminate\Support\Facades\Redis;
use Maximus\Fail2Ban\Contracts\AllowlistRepository;
use Maximus\Fail2Ban\Contracts\AuditRepository;
use Maximus\Fail2Ban\Contracts\BanRepository;
use Maximus\Fail2Ban\Contracts\IncidentRepository;
use Maximus\Fail2Ban\Contracts\SettingsRepository;
use Maximus\Fail2Ban\Contracts\StatsRepository;
use Maximus\Fail2Ban\Tests\Support\InteractsWithFail2BanRedis;
use Maximus\Fail2Ban\Tests\Support\RedisRoundTrips;
use Maximus\Fail2Ban\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;

/**
 * 往返次数：测试进程与 Redis 之间夹一个 TCP 转发器（tests/Support/redis-proxy.php），
 * 数「客户端在收到上一次回复之后又发出请求」的次数，也就是真实的网络往返。
 *
 * 不用 Laravel 的 CommandExecuted 事件：PhpRedisConnection::pipeline() 不经过 command()，
 * 管道里的命令根本不触发事件，数出来是 0，证明不了什么。
 */
class RoundTripTest extends TestCase
{
    use InteractsWithFail2BanRedis;

    private const V = '203.0.113.47';

    private const REPEAT = ['enabled' => true, 'factor' => 2, 'max_days' => 7, 'keep_days' => 7];

    private RedisRoundTrips $proxy;

    protected function setUp(): void
    {
        parent::setUp();

        $this->proxy = $this->proxyFail2BanRedis();
    }

    protected function tearDown(): void
    {
        Redis::purge('fail2ban');
        $this->proxy->stop();

        parent::tearDown();
    }

    /**
     * 先把连接建好（握手的往返不算在被测操作里）。
     */
    private function warm(): void
    {
        Redis::connection('fail2ban')->ping();
    }

    #[Test]
    public function a_cold_lookup_costs_the_connection_handshake_plus_one(): void
    {
        $bans = $this->app->make(BanRepository::class);

        // 宿主连接配置里有 database 时，Laravel 的连接器在连上后发一次 SELECT。
        $this->assertSame(2, $this->proxy->count(fn () => $bans->lookup(self::V)));
        $this->assertSame(1, $this->proxy->connections());
    }

    #[Test]
    public function every_hot_path_write_is_one_round_trip(): void
    {
        $bans = $this->app->make(BanRepository::class);
        $stats = $this->app->make(StatsRepository::class);
        $incidents = $this->app->make(IncidentRepository::class);
        $this->warm();

        $trips = [
            'recordHits (one hit + its stats)' => $this->proxy->count(fn () => $bans->recordHits(self::V, [
                ['rule' => 'not-found-scan', 'dedupe' => '/b', 'record' => ['time' => 1762500000, 'method' => 'GET', 'path' => '/b'], 'window' => 5],
            ], 100, '/b', '荷兰')),
            'recordHits (two hits + their stats)' => $this->proxy->count(fn () => $bans->recordHits(self::V, [
                ['rule' => 'not-found-scan', 'dedupe' => '/c', 'record' => ['time' => 1762500000, 'method' => 'GET', 'path' => '/c'], 'window' => 5],
                ['rule' => 'scanner-agent', 'dedupe' => null, 'record' => ['time' => 1762500000, 'method' => 'GET', 'path' => '/c'], 'window' => 10],
            ], 100, '/c', null)),
            'ban' => $this->proxy->count(fn () => $bans->ban(self::V, ['incident' => 'BAN-20261107-AAAAAA', 'rule' => 'not-found-scan'], 30, self::REPEAT)),
            'ban (already banned)' => $this->proxy->count(fn () => $bans->ban(self::V, ['incident' => 'BAN-20261107-BBBBBB', 'rule' => 'not-found-scan'], 30, self::REPEAT)),
            'incrementBans' => $this->proxy->count(fn () => $stats->incrementBans()),
            'incident record' => $this->proxy->count(fn () => $incidents->record(['visitor' => self::V, 'disposition' => 'banned'])),
            'recordBlock' => $this->proxy->count(fn () => $bans->recordBlock(self::V)),
            'incrementBlocked' => $this->proxy->count(fn () => $stats->incrementBlocked()),
        ];

        $this->assertSame(array_fill_keys(array_keys($trips), 1), $trips);
    }

    #[Test]
    public function record_hits_records_every_hit_and_its_stats(): void
    {
        $bans = $this->app->make(BanRepository::class);
        $stats = $this->app->make(StatsRepository::class);

        $hits = [
            ['rule' => 'not-found-scan', 'dedupe' => '/a', 'record' => ['time' => 1762500000, 'method' => 'GET', 'path' => '/a'], 'window' => 5],
            ['rule' => 'not-found-scan', 'dedupe' => '/a', 'record' => ['time' => 1762500001, 'method' => 'GET', 'path' => '/a'], 'window' => 5],
            ['rule' => 'scanner-agent', 'dedupe' => null, 'record' => ['time' => 1762500002, 'method' => 'GET', 'path' => '/a'], 'window' => 10],
        ];

        $this->assertSame([
            ['count' => 1, 'added' => true],
            ['count' => 1, 'added' => false],   // 同一个去重键只记一次
            ['count' => 1, 'added' => true],
        ], $bans->recordHits(self::V, $hits, 100, '/a', 'NL'));

        $this->assertSame([
            'not-found-scan' => [['time' => 1762500000, 'method' => 'GET', 'path' => '/a']],
            'scanner-agent' => [['time' => 1762500002, 'method' => 'GET', 'path' => '/a']],
        ], $bans->hits(self::V));
        $this->assertGreaterThan(0, $this->redis()->ttl('fail2ban:hits:not-found-scan:'.self::V));
        $this->assertGreaterThan(0, $this->redis()->ttl('fail2ban:hits:scanner-agent:'.self::V));

        // 统计按每条命中算，去重没记上的那条也算（与改动前逐条写统计相同）
        $this->assertSame(3, $stats->trend(1)[0]['hits']);
        $this->assertSame([['key' => self::V, 'count' => 3]], $stats->top('ip'));
        $this->assertSame([['key' => '/a', 'count' => 3]], $stats->top('target'));
        $this->assertSame([['key' => 'NL', 'count' => 3]], $stats->top('region'));
        $this->assertSame([], $bans->recordHits(self::V, [], 100));
    }

    #[Test]
    public function panel_operations_have_a_fixed_small_number_of_round_trips(): void
    {
        $bans = $this->app->make(BanRepository::class);
        $allow = $this->app->make(AllowlistRepository::class);
        $this->warm();

        $trips = [
            'banManually' => $this->proxy->count(fn () => $bans->banManually(self::V, ['incident' => 'BAN-20261107-AAAAAA', 'operator' => 'admin'], 10)),
            'find' => $this->proxy->count(fn () => $bans->find(self::V)),
            'hits' => $this->proxy->count(fn () => $bans->hits(self::V)),
            'unban' => $this->proxy->count(fn () => $bans->unban(self::V)),
            'markUnbanned' => $this->proxy->count(fn () => $this->app->make(IncidentRepository::class)->markUnbanned('BAN-20261107-AAAAAA')),
            'audit record' => $this->proxy->count(fn () => $this->app->make(AuditRepository::class)->record('admin', 'unban', self::V)),
            'settings all' => $this->proxy->count(fn () => $this->app->make(SettingsRepository::class)->all()),
            'allowlist (panel entry)' => $this->proxy->count(fn () => $allow->match(self::V)),
        ];

        $this->assertSame(array_fill_keys(array_keys($trips), 1), $trips);

        // 命中内置段时不访问 Redis
        $this->assertSame(0, $this->proxy->count(fn () => $allow->match('10.0.0.1')));
        // 名单：清理与读取索引一次，取各封禁一次
        $bans->banManually(self::V, ['incident' => 'BAN-20261107-AAAAAA', 'operator' => 'admin'], 10);
        $this->assertSame(2, $this->proxy->count(fn () => $bans->all()));
    }
}
