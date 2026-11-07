<?php

namespace Maximus\Fail2Ban\Tests\Feature\Storage;

use Carbon\CarbonImmutable;
use Maximus\Fail2Ban\Contracts\StatsRepository;
use Maximus\Fail2Ban\Tests\Support\InteractsWithFail2BanRedis;
use Maximus\Fail2Ban\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;

class StatsRepositoryTest extends TestCase
{
    use InteractsWithFail2BanRedis;

    private StatsRepository $stats;

    protected function setUp(): void
    {
        parent::setUp();

        $this->stats = $this->app->make(StatsRepository::class);

        // 固定在一个小时的中间，避免跨小时
        $this->travelTo(CarbonImmutable::parse('2026-11-07 14:30:00'));
    }

    #[Test]
    public function hits_blocks_and_bans_are_counted_per_hour(): void
    {
        $this->recordHit('not-found-scan', '203.0.113.47', target: '/wp-login.php', region: '荷兰');
        $this->recordHit('not-found-scan', '203.0.113.47', target: '/.env');
        $this->recordHit('scanner-agent', '198.51.100.1');
        $this->stats->incrementBlocked();
        $this->stats->incrementBlocked();
        $this->stats->incrementBlocked();
        $this->stats->incrementBans();

        $this->assertSame(
            ['hits:not-found-scan' => '2', 'hits:scanner-agent' => '1', 'blocked' => '3', 'bans' => '1'],
            $this->redis()->hgetall('fail2ban:stats:2026110714')
        );

        $trend = $this->stats->trend(3);
        $this->assertSame([
            CarbonImmutable::parse('2026-11-07 12:00')->getTimestamp(),
            CarbonImmutable::parse('2026-11-07 13:00')->getTimestamp(),
            CarbonImmutable::parse('2026-11-07 14:00')->getTimestamp(),
        ], array_column($trend, 'hour'));
        $this->assertSame([0, 0, 3], array_column($trend, 'hits'));
        $this->assertSame([0, 0, 3], array_column($trend, 'blocked'));
        $this->assertSame([0, 0, 1], array_column($trend, 'bans'));
        $this->assertSame(
            ['not-found-scan' => 2, 'sensitive-path' => 0, 'scanner-agent' => 1, 'attack-pattern' => 0, 'known-exploit' => 0],
            $trend[2]['rules']
        );

        $this->travelTo(CarbonImmutable::parse('2026-11-07 15:10:00'));
        $this->recordHit('known-exploit', '203.0.113.47');

        $trend = collect($this->stats->trend(24));
        $this->assertSame([4, 3, 1], [$trend->sum('hits'), $trend->sum('blocked'), $trend->sum('bans')]);
        $this->assertSame(['not-found-scan' => 0, 'sensitive-path' => 0, 'scanner-agent' => 0, 'attack-pattern' => 0, 'known-exploit' => 1], $this->stats->trend(1)[0]['rules']);
        $this->assertSame(1, $this->stats->trend(1)[0]['hits']);
    }

    #[Test]
    public function daily_rankings_accumulate(): void
    {
        $this->recordHit('not-found-scan', '203.0.113.47', target: '/wp-login.php', region: '荷兰');
        $this->recordHit('not-found-scan', '203.0.113.47', target: '/.env', region: '荷兰');
        $this->recordHit('sensitive-path', '198.51.100.1', target: '/.env', region: '美国');

        $this->assertSame([['key' => '203.0.113.47', 'count' => 2], ['key' => '198.51.100.1', 'count' => 1]], $this->stats->top('ip'));
        $this->assertSame([['key' => '/.env', 'count' => 2], ['key' => '/wp-login.php', 'count' => 1]], $this->stats->top('target'));
        $this->assertSame([['key' => '荷兰', 'count' => 2]], $this->stats->top('region', 1));

        // 换一天：当天排行从零开始，按天数合并
        $this->travelTo(CarbonImmutable::parse('2026-11-08 09:00:00'));
        $this->recordHit('not-found-scan', '198.51.100.1', target: '/admin');

        $this->assertSame([['key' => '198.51.100.1', 'count' => 1]], $this->stats->top('ip'));
        $this->assertSame([['key' => '198.51.100.1', 'count' => 2], ['key' => '203.0.113.47', 'count' => 2]], $this->stats->top('ip', 10, 2));
    }

    #[Test]
    public function rankings_keep_only_the_top_200(): void
    {
        // 前 5 名多命中几次，确保留下来的是真正的前几名
        foreach (range(1, 5) as $i) {
            foreach (range(1, 3) as $_) {
                $this->recordHit('not-found-scan', "10.9.0.{$i}");
            }
        }

        foreach (range(1, 250) as $i) {
            $this->recordHit('not-found-scan', '10.8.'.intdiv($i, 256).'.'.($i % 256));
        }

        $this->assertSame(200, $this->redis()->zcard('fail2ban:top:ip:20261107'));
        $this->assertSame(['10.9.0.1', '10.9.0.2', '10.9.0.3', '10.9.0.4', '10.9.0.5'], array_column($this->stats->top('ip', 5), 'key'));
        $this->assertCount(200, $this->stats->top('ip', 1000));
    }

    #[Test]
    public function every_stats_key_expires_after_stats_days(): void
    {
        config(['fail2ban.stats_days' => 30]);

        $this->recordHit('not-found-scan', '203.0.113.47', target: '/a', region: '荷兰');
        $this->stats->incrementBlocked();

        $now = CarbonImmutable::now()->getTimestamp();
        $hourExpiry = CarbonImmutable::parse('2026-11-07 14:00')->addDays(30)->addHour()->getTimestamp();
        $dayExpiry = CarbonImmutable::parse('2026-11-07 00:00')->addDays(31)->getTimestamp();

        // 用的是 EXPIREAT（绝对时刻），按真实时钟读出的 TTL 换算回绝对时刻比较
        $absolute = fn (string $key) => time() + $this->redis()->ttl($key);

        $this->assertEqualsWithDelta($hourExpiry, $absolute('fail2ban:stats:2026110714'), 2);

        foreach (['ip', 'target', 'region'] as $category) {
            $this->assertEqualsWithDelta($dayExpiry, $absolute("fail2ban:top:{$category}:20261107"), 2, $category);
        }

        $this->assertGreaterThan($now, $hourExpiry);
    }
}
