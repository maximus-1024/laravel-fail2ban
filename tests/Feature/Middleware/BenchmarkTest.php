<?php

namespace Maximus\Fail2Ban\Tests\Feature\Middleware;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Redis;
use Maximus\Fail2Ban\Http\Middleware\BlockBannedIps;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\HttpFoundation\Response;

/**
 * 基准（只设很宽的防退化上限，数字写到 STDERR 供验收报告引用）：
 *  - 正常请求进入检查（handle）的耗时，持久连接与非持久连接各一组；
 *  - 正常请求收尾（terminate）的耗时；
 *  - 跨请求复用连接时每个请求的真实往返数（phpredis 复用持久连接时会先发 ECHO 检查连接是否还活着）。
 *
 * 「下一个请求」的模拟：像 php-fpm 那样丢掉 Redis 管理器与连接对象，但不调用 close()——
 * 非持久连接随对象销毁而断开，下一次重新握手；持久连接留在 phpredis 的连接池里被复用。
 */
#[Group('benchmark')]
class BenchmarkTest extends MiddlewareTestCase
{
    private const ITERATIONS = 1000;

    private const WARMUP = 50;

    private BlockBannedIps $middleware;

    protected function setUp(): void
    {
        parent::setUp();

        $this->middleware = $this->app->make(BlockBannedIps::class);
    }

    private function request(): Request
    {
        return Request::create('/ok', 'GET', [], [], [], ['REMOTE_ADDR' => self::IP, 'HTTP_USER_AGENT' => 'Mozilla/5.0']);
    }

    /**
     * 连接配置的几种组合：
     *  - persistent：phpredis 持久连接；
     *  - select：连接配置里有 database 时，Laravel 的连接器每次建连接（包括从持久连接池取出）都发一次 SELECT；
     *  - echo：phpredis 从持久连接池取出连接时先发 ECHO 检查是否还活着（redis.pconnect.echo_check_liveness，默认 1）。
     */
    private function useConnection(bool $persistent, bool $select = true, bool $echo = true): void
    {
        ini_set('redis.pconnect.echo_check_liveness', $echo ? '1' : '0');

        $this->reconfigureFail2BanRedis([
            'options.persistent' => $persistent,
            'persistent_id' => $persistent ? 'f2b-bench-'.getmypid().($select ? '-s' : '').($echo ? '-e' : '') : null,
            'database' => $select ? 0 : null,
        ]);
    }

    protected function tearDown(): void
    {
        ini_restore('redis.pconnect.echo_check_liveness');

        parent::tearDown();
    }

    /**
     * @return array{median: float, p95: float} 微秒
     */
    private function measureHandle(bool $perRequestConnection): array
    {
        $next = fn () => new Response('ok');
        $samples = [];

        for ($i = 0; $i < self::WARMUP + self::ITERATIONS; $i++) {
            if ($perRequestConnection) {
                $this->nextRequest();
            }

            $request = $this->request();

            $started = hrtime(true);
            $this->middleware->handle($request, $next);
            $elapsed = (hrtime(true) - $started) / 1000;

            $this->assertSame(BlockBannedIps::CLEAN, $request->attributes->get(BlockBannedIps::ATTRIBUTE)['state']);

            if ($i >= self::WARMUP) {
                $samples[] = $elapsed;
            }
        }

        return $this->summary($samples);
    }

    private function summary(array $samples): array
    {
        sort($samples);

        return [
            'median' => round($samples[intdiv(count($samples), 2)], 1),
            'p95' => round($samples[(int) floor(count($samples) * 0.95)], 1),
        ];
    }

    #[Test]
    public function entry_check_and_terminate_timings(): void
    {
        $results = [];

        $this->useConnection(false);
        $results['handle, connection kept within process (warm)'] = $this->measureHandle(false);
        $results['handle, non-persistent, new connection per request'] = $this->measureHandle(true);

        $this->useConnection(true);
        $results['handle, persistent, reused (SELECT + ECHO)'] = $this->measureHandle(true);

        $this->useConnection(true, select: false, echo: false);
        $results['handle, persistent, reused (no SELECT, no ECHO)'] = $this->measureHandle(true);

        // 收尾：正常请求（200、没有命中）
        $samples = [];
        $next = fn () => new Response('ok');

        for ($i = 0; $i < self::WARMUP + self::ITERATIONS; $i++) {
            $request = $this->request();
            $response = $this->middleware->handle($request, $next);

            $started = hrtime(true);
            $this->app->make(BlockBannedIps::class)->terminate($request, $response);
            $elapsed = (hrtime(true) - $started) / 1000;

            if ($i >= self::WARMUP) {
                $samples[] = $elapsed;
            }
        }

        $results['terminate, normal request (no hit)'] = $this->summary($samples);

        foreach ($results as $label => $r) {
            fwrite(STDERR, sprintf("[bench] %-55s median %8.1f us   p95 %8.1f us\n", $label, $r['median'], $r['p95']));
        }

        // 只防退化：上限放得很宽
        foreach ($results as $label => $r) {
            $this->assertLessThan(20000, $r['median'], $label);
        }

        $this->assertSame([], $this->hitCounts());
    }
}
