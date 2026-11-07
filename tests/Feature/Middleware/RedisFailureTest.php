<?php

namespace Maximus\Fail2Ban\Tests\Feature\Middleware;

use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Redis;
use Maximus\Fail2Ban\Http\Middleware\BlockBannedIps;
use Maximus\Fail2Ban\Tests\Support\RedisRoundTrips;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\Test;

/**
 * Redis 不可用或超时：每个请求都放行，响应与未启用时一致，收尾不再碰 Redis。
 *
 * 测试连接的 timeout 与 read_timeout 都是 0.2 秒（REDIS_TIMEOUT）。
 */
class RedisFailureTest extends MiddlewareTestCase
{
    /** @var resource|null */
    private $blackhole = null;

    private ?RedisRoundTrips $proxy = null;

    protected function tearDown(): void
    {
        Redis::purge('fail2ban');
        $this->proxy?->stop();

        if ($this->blackhole) {
            fclose($this->blackhole);
        }

        parent::tearDown();
    }

    /**
     * 一个只接受连接、从不回复的端口：连得上，读必然超时。
     */
    private function blackholePort(): int
    {
        $this->blackhole = stream_socket_server('tcp://127.0.0.1:0');

        return (int) substr(strrchr(stream_socket_get_name($this->blackhole, false), ':'), 1);
    }

    /**
     * 一个没人监听的端口：连接被拒绝。
     */
    private function closedPort(): int
    {
        $socket = stream_socket_server('tcp://127.0.0.1:0');
        $port = (int) substr(strrchr(stream_socket_get_name($socket, false), ':'), 1);
        fclose($socket);

        return $port;
    }

    /**
     * 同一组请求的 [状态码, 内容]。
     */
    private function responses(): array
    {
        $out = [];

        foreach (['/ok', '/orders/1', '/nope', '/_ignition/execute-solution'] as $uri) {
            $response = $this->api($uri, ['User-Agent' => 'sqlmap/1.7']);
            $out[$uri] = [$response->getStatusCode(), $response->getContent()];
        }

        return $out;
    }

    /**
     * Redis 拒绝连接时发同一组请求。
     *
     * @return array{0: array, 1: array, 2: float} [未启用时的响应, 实际响应, 耗时秒数]
     */
    private function whileRedisRefusesConnections(): array
    {
        config(['app.debug' => false]);
        $this->setMode('block');

        config(['fail2ban.enabled' => false]);
        $expected = $this->responses();
        config(['fail2ban.enabled' => true]);

        $this->reconfigureFail2BanRedis(['host' => '127.0.0.1', 'port' => $this->closedPort()]);
        Log::spy();

        $started = hrtime(true);
        $actual = $this->responses();

        return [$expected, $actual, (hrtime(true) - $started) / 1e9];
    }

    /**
     * Redis 读超时（转发器后面是一个从不回复的端口）时逐个发同一组请求。
     *
     * @return array{0: array, 1: array, 2: array<string, float>, 3: array<string, ?string>} [未启用时的响应, 实际响应, 各请求耗时秒数, 各请求进入阶段的状态]
     */
    private function whileRedisTimesOut(): array
    {
        config(['app.debug' => false]);

        config(['fail2ban.enabled' => false]);
        $expected = $this->responses();
        config(['fail2ban.enabled' => true]);

        $this->proxy = new RedisRoundTrips('127.0.0.1', $this->blackholePort());
        $this->reconfigureFail2BanRedis(['host' => '127.0.0.1', 'port' => $this->proxy->port]);
        Log::spy();

        $actual = $durations = $states = [];

        foreach (['/ok', '/orders/1', '/nope', '/_ignition/execute-solution'] as $uri) {
            $started = hrtime(true);
            $response = $this->api($uri, ['User-Agent' => 'sqlmap/1.7']);
            $durations[$uri] = (hrtime(true) - $started) / 1e9;
            $actual[$uri] = [$response->getStatusCode(), $response->getContent()];
            $states[$uri] = $this->app['request']->attributes->get(BlockBannedIps::ATTRIBUTE)['state'] ?? null;
        }

        return [$expected, $actual, $durations, $states];
    }

    #[Test]
    public function when_redis_refuses_connections_every_request_passes_like_when_disabled(): void
    {
        $runs = static::$controllerRuns;

        [$expected, $actual] = $this->whileRedisRefusesConnections();

        $this->assertSame($expected, $actual);
        $this->assertSame($runs + 4, static::$controllerRuns);
        Log::shouldHaveReceived('warning')->times(4);
        Log::shouldNotHaveReceived('error');
    }

    #[Test]
    #[Group('benchmark')]
    public function refused_connections_fail_fast(): void
    {
        [, , $elapsed] = $this->whileRedisRefusesConnections();

        fwrite(STDERR, sprintf("connection refused: 4 requests in %.3fs\n", $elapsed));
        $this->assertLessThan(1.0, $elapsed, "4 requests took {$elapsed}s");
    }

    #[Test]
    public function when_redis_times_out_requests_pass_and_terminate_does_not_retry(): void
    {
        [$expected, $actual, , $states] = $this->whileRedisTimesOut();

        $this->assertSame($expected, $actual);
        $this->assertSame(array_fill_keys(array_keys($states), BlockBannedIps::FAILED), $states);

        // 每个请求只在进入时试了一次；收尾（包括命中规则的 404 与扫描器请求）没有再发命令
        $this->assertSame(4, $this->proxy->trips());
        Log::shouldHaveReceived('warning')->times(4);
        Log::shouldNotHaveReceived('error');
    }

    #[Test]
    #[Group('benchmark')]
    public function timed_out_requests_pass_within_the_timeout(): void
    {
        [, , $durations] = $this->whileRedisTimesOut();

        foreach ($durations as $uri => $seconds) {
            fwrite(STDERR, sprintf("timeout request %-32s %.3fs\n", $uri, $seconds));
            // REDIS_TIMEOUT 是 0.2 秒；留出 Testbench 处理请求本身的余量
            $this->assertLessThan(0.6, $seconds, "{$uri} took {$seconds}s");
        }
    }

    #[Test]
    public function a_failure_after_the_entry_read_is_swallowed_and_logged(): void
    {
        $this->setMode('block');
        Log::spy();

        // 进入时读取正常；收尾写入时 Redis 已不可用
        static::$probe = fn () => $this->reconfigureFail2BanRedis(['host' => '127.0.0.1', 'port' => $this->closedPort()]);

        $this->api('/ok', ['User-Agent' => 'sqlmap/1.7'])->assertOk();

        Log::shouldHaveReceived('error')->once();

        // 后续请求不受影响
        static::$probe = null;
        $this->reconfigureFail2BanRedis(['port' => (int) env('FAIL2BAN_TEST_REDIS_PORT', 6379), 'host' => env('FAIL2BAN_TEST_REDIS_HOST', '127.0.0.1')]);
        $this->api('/ok', ['User-Agent' => 'sqlmap/1.7'])->assertOk();
        $this->assertSame(['scanner-agent' => 1], $this->hitCounts());
    }
}
