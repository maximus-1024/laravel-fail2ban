<?php

namespace Maximus\Fail2Ban\Tests\Feature\Middleware;

use Illuminate\Http\Middleware\TrustProxies;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Redis;
use Illuminate\Testing\TestResponse;
use Maximus\Fail2Ban\Contracts\BanRepository;
use Maximus\Fail2Ban\Contracts\IncidentRepository;
use Maximus\Fail2Ban\Contracts\SettingsRepository;
use Maximus\Fail2Ban\Http\Middleware\BlockBannedIps;
use Maximus\Fail2Ban\Tests\Support\InteractsWithFail2BanRedis;
use Maximus\Fail2Ban\Tests\TestCase;
use Maximus\Fail2Ban\Visitor;
use RuntimeException;
use Symfony\Component\HttpFoundation\Response;

/**
 * 中间件端到端测试的最小应用：Testbench 的真实 HTTP Kernel（含框架默认的全局中间件与 TrustProxies）、
 * 几条真实路由、真实 Redis（phpredis）。
 *
 * 每个请求都走 handle → 路由 → terminate（Laravel 测试的 call() 会调用 Kernel::terminate()）。
 */
abstract class MiddlewareTestCase extends TestCase
{
    use InteractsWithFail2BanRedis;

    protected const IP = '203.0.113.47';

    protected const OTHER_IP = '198.51.100.23';

    /**
     * 控制器（路由闭包）执行次数，用来证明拒绝发生在路由之前。
     */
    public static int $controllerRuns = 0;

    /**
     * 控制器执行时调用的探针（例如记下当时的 Redis 往返数）。
     *
     * @var (\Closure(): void)|null
     */
    public static ?\Closure $probe = null;

    protected function setUp(): void
    {
        parent::setUp();

        static::$controllerRuns = 0;
        static::$probe = null;
    }

    protected function tearDown(): void
    {
        TrustProxies::flushState();
        Redis::purge('fail2ban');
        static::$probe = null;

        parent::tearDown();
    }

    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);

        $app['config']->set('fail2ban.enabled', true);
        $app['config']->set('app.timezone', 'Asia/Shanghai');
    }

    protected function defineRoutes($router): void
    {
        $run = function () {
            static::$controllerRuns++;

            if (static::$probe) {
                (static::$probe)();
            }
        };

        $router->get('/ok', function () use ($run) {
            $run();

            return response()->json(['code' => 0, 'message' => 'ok']);
        });

        // 业务层「订单不存在」：HTTP 200，内容里的 code 是 404
        $router->get('/orders/{id}', function () use ($run) {
            $run();

            return response()->json(['code' => 404, 'message' => '订单不存在']);
        });

        $router->get('/boom', function () use ($run) {
            $run();

            throw new RuntimeException('boom');
        });

        $router->put('/items/{id}', function () use ($run) {
            $run();

            return response()->json(['code' => 0]);
        });

        $router->delete('/items/{id}', function () use ($run) {
            $run();

            return response()->json(['code' => 0]);
        });
    }

    /**
     * 以某个访客的身份发一个请求。$headers 是普通请求头（如 User-Agent、Accept）。
     */
    protected function visit(string $uri, array $headers = [], string $ip = self::IP, string $method = 'GET'): TestResponse
    {
        $server = $this->transformHeadersToServerVars($headers) + ['REMOTE_ADDR' => $ip];

        return $this->call($method, $uri, [], [], [], $server);
    }

    /**
     * 以 JSON 客户端（Accept: *∕*）发请求。Symfony 的测试请求默认带浏览器的 Accept，接口调用要显式换掉。
     */
    protected function api(string $uri, array $headers = [], string $ip = self::IP, string $method = 'GET'): TestResponse
    {
        return $this->visit($uri, $headers + ['Accept' => '*/*'], $ip, $method);
    }

    protected function setMode(string $mode): void
    {
        $this->settings()->save(['mode' => $mode], 'test');
    }

    protected function setRule(string $rule, array $changes): void
    {
        $this->settings()->save(['rules' => [$rule => $changes]], 'test');
    }

    protected function settings(): SettingsRepository
    {
        return $this->app->make(SettingsRepository::class);
    }

    protected function bans(): BanRepository
    {
        return $this->app->make(BanRepository::class);
    }

    protected function ban(string $ip = self::IP): ?array
    {
        return $this->bans()->find(Visitor::key($ip));
    }

    /**
     * @return array<string, int> 规则 => 现有命中条数
     */
    protected function hitCounts(string $ip = self::IP): array
    {
        return array_map('count', $this->bans()->hits(Visitor::key($ip)));
    }

    /**
     * @return list<array>
     */
    protected function incidents(): array
    {
        return $this->app->make(IncidentRepository::class)->paginate([], 1, 500)['data'];
    }

    /**
     * 一个没有被封、没有命中规则的正常请求：直接调用中间件的进入与收尾（不经过 HTTP Kernel，只数中间件自己的往返）。
     */
    protected function normalRequest(): void
    {
        $request = Request::create('/ok', 'GET', [], [], [], ['REMOTE_ADDR' => self::IP, 'HTTP_USER_AGENT' => 'Mozilla/5.0']);
        $response = $this->app->make(BlockBannedIps::class)->handle($request, fn () => new Response('ok'));

        $state = $request->attributes->get(BlockBannedIps::ATTRIBUTE)['state'];

        if ($state !== BlockBannedIps::CLEAN) {
            try {
                $this->app->make(BanRepository::class)->lookup(self::IP);
                $reason = 'lookup succeeded on retry';
            } catch (\Throwable $e) {
                $reason = $e::class.': '.$e->getMessage();
            }

            $this->fail("entry state {$state}: {$reason}");
        }

        $this->app->make(BlockBannedIps::class)->terminate($request, $response);
    }
}
