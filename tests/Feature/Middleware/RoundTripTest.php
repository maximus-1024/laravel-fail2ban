<?php

namespace Maximus\Fail2Ban\Tests\Feature\Middleware;

use Illuminate\Support\Facades\Redis;
use Maximus\Fail2Ban\Tests\Support\RedisRoundTrips;
use Maximus\Fail2Ban\Visitor;
use PHPUnit\Framework\Attributes\Test;

/**
 * 真实的 Redis 往返数：测试进程与 Redis 之间夹 tests/Support/redis-proxy.php。
 *
 * 连接先建好（宿主开持久连接，握手不算在请求里），之后数整个请求（进入 + 路由 + 收尾）的往返，
 * 并在控制器里记下当时的往返数，证明那一次发生在进入业务之前。
 */
class RoundTripTest extends MiddlewareTestCase
{
    private RedisRoundTrips $proxy;

    /**
     * 控制器执行时的往返数（相对请求开始）。
     */
    private ?int $atController = null;

    private int $start = 0;

    protected function setUp(): void
    {
        parent::setUp();

        $this->proxy = $this->proxyFail2BanRedis();

        static::$probe = function () {
            $this->atController = $this->proxy->trips() - $this->start;
        };
    }

    protected function tearDown(): void
    {
        Redis::purge('fail2ban');
        $this->proxy->stop();

        parent::tearDown();
    }

    /**
     * 发一个请求，返回 [整个请求的往返数, 控制器执行时的往返数（没执行为 null）]。
     */
    private function trips(string $uri, array $headers = [], string $method = 'GET', string $ip = self::IP): array
    {
        Redis::connection('fail2ban')->ping(); // 连接已建立

        $this->atController = null;
        $this->start = $this->proxy->trips();

        $this->api($uri, $headers, $ip, $method);

        return [$this->proxy->trips() - $this->start, $this->atController];
    }

    #[Test]
    public function a_normal_request_costs_exactly_one_round_trip_before_the_controller_and_none_after(): void
    {
        foreach (['observe', 'block'] as $mode) {
            $this->setMode($mode);

            $this->assertSame([1, 1], $this->trips('/ok'), $mode);
            $this->assertSame([1, 1], $this->trips('/orders/404'), $mode);
            $this->assertSame([1, 1], $this->trips('/boom'), $mode);
            $this->assertSame([1, 1], $this->trips('/items/1', [], 'PUT'), $mode);
            $this->assertSame([1, 1], $this->trips('/items/1', [], 'DELETE'), $mode);
            $this->assertSame([1, 1], $this->trips('/ok', ['User-Agent' => 'curl/8.5.0']), $mode);
            $this->assertSame([1, 1], $this->trips('/ok?notify_url=https%3A%2F%2Fm.example.com%2Fcb'), $mode);
        }

        $this->assertSame([], $this->hitCounts());
    }

    #[Test]
    public function mode_off_costs_the_entry_read_only(): void
    {
        $this->setMode('off');

        $this->assertSame([1, 1], $this->trips('/ok'));
        $this->assertSame([1, null], $this->trips('/_ignition/execute-solution'));
    }

    #[Test]
    public function round_trips_of_hit_ban_and_blocked_requests(): void
    {
        $this->setMode('block');

        $counts = [
            // 进入 1 + 白名单面板条目 1 + 记命中连同统计 1（一个管道）
            'one hit, below count' => $this->trips('/nope-1')[0],
            // 两条规则的记命中与统计也在同一个管道里
            'two hits, below count' => $this->trips('/ok?q=1%20UnIoN%20SeLeCt%201', ['User-Agent' => 'sqlmap/1.7'])[0],
            // 上面 3 次 + 封禁 1 + 攻击事件 1 + 封禁统计 1
            'hit that bans' => $this->trips('/_ignition/execute-solution')[0],
            // 进入 1，在路由之前拒绝；收尾 被拦次数 1 + 拦截统计 1
            'blocked' => $this->trips('/ok'),
        ];

        fwrite(STDERR, 'round trips: '.json_encode($counts)."\n");

        $this->assertSame([
            'one hit, below count' => 3,
            'two hits, below count' => 3,
            'hit that bans' => 6,
            'blocked' => [3, null],
        ], $counts);

        $this->assertNotNull($this->bans()->find(Visitor::key(self::IP)));
    }

    #[Test]
    public function observe_mode_with_a_ban_costs_the_same_as_blocked(): void
    {
        $this->bans()->banManually(Visitor::key(self::IP), ['incident' => 'BAN-20261107-AAAAAA', 'operator' => 't'], 10);

        $this->assertSame([3, 1], $this->trips('/ok'));
    }

    /**
     * IPv6 的封禁键是 64 位网段，命中时再按真实地址查白名单（面板条目一次往返）与宿主豁免（不碰 Redis）。
     * IPv4 被拦与正常请求的往返数不变。
     */
    #[Test]
    public function an_ipv6_network_ban_costs_one_more_round_trip_to_check_the_real_address(): void
    {
        $this->setMode('block');
        $this->app->make(\Maximus\Fail2Ban\Contracts\AllowlistRepository::class)->add('2001:db8:4c2:91::5', '办公室', 'admin');
        $this->bans()->banManually('2001:db8:4c2:91::/64', ['incident' => 'BAN-20261107-AAAAAA', 'operator' => 't'], 10);
        $this->bans()->banManually(self::OTHER_IP, ['incident' => 'BAN-20261107-BBBBBB', 'operator' => 't'], 10);

        $counts = [
            // 进入 1 + 白名单面板条目 1，在路由之前拒绝；收尾 被拦次数 1 + 拦截统计 1
            'ipv6 network blocked' => $this->trips('/ok', ip: '2001:db8:4c2:91::6'),
            // 进入 1 + 白名单面板条目 1，放行；没有命中规则，收尾 0
            'ipv6 allowlisted in a banned network' => $this->trips('/ok', ip: '2001:db8:4c2:91::5'),
            // IPv4 的封禁键就是地址本身，不查白名单：进入 1；收尾 2
            'ipv4 blocked' => $this->trips('/ok', ip: self::OTHER_IP),
            'ipv6 normal' => $this->trips('/ok', ip: '2001:db8:aaaa::1'),
            'ipv4 normal' => $this->trips('/ok'),
        ];

        fwrite(STDERR, 'round trips: '.json_encode($counts)."\n");

        $this->assertSame([
            'ipv6 network blocked' => [4, null],
            'ipv6 allowlisted in a banned network' => [2, 2],
            'ipv4 blocked' => [3, null],
            'ipv6 normal' => [1, 1],
            'ipv4 normal' => [1, 1],
        ], $counts);
    }
}
