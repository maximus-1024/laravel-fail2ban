<?php

namespace Maximus\Fail2Ban\Tests\Feature\Middleware;

use Illuminate\Contracts\Http\Kernel;
use Illuminate\Http\Middleware\TrustProxies;
use Maximus\Fail2Ban\Contracts\BanRepository;
use Maximus\Fail2Ban\Http\Middleware\BlockBannedIps;
use Maximus\Fail2Ban\Visitor;
use PHPUnit\Framework\Attributes\Test;

/**
 * 中间件的位置与两个「什么都不做」的开关。
 */
class RegistrationTest extends MiddlewareTestCase
{
    #[Test]
    public function it_is_the_last_global_middleware_after_trust_proxies(): void
    {
        $global = $this->app->make(Kernel::class)->getGlobalMiddleware();

        $this->assertSame(BlockBannedIps::class, end($global));
        $this->assertContains(TrustProxies::class, $global);
        $this->assertGreaterThan(
            array_search(TrustProxies::class, $global, true),
            array_search(BlockBannedIps::class, $global, true),
        );
        $this->assertCount(1, array_keys($global, BlockBannedIps::class, true));
    }

    #[Test]
    public function when_disabled_responses_are_identical_to_an_app_without_the_middleware(): void
    {
        // 调试页里有调用栈，栈里会出现中间件本身；比较的是线上的样子
        config(['fail2ban.enabled' => false, 'app.debug' => false]);

        $uris = ['/ok', '/orders/1', '/boom', '/_ignition/execute-solution', '/.env', '/nope'];

        $with = array_map(fn ($uri) => $this->snapshot($this->api($uri, ['User-Agent' => 'sqlmap/1.7'])), $uris);

        $kernel = $this->app->make(Kernel::class);
        $kernel->setGlobalMiddleware(array_values(array_diff($kernel->getGlobalMiddleware(), [BlockBannedIps::class])));

        $without = array_map(fn ($uri) => $this->snapshot($this->api($uri, ['User-Agent' => 'sqlmap/1.7'])), $uris);

        $this->assertSame($without, $with);
        $this->assertSame([], $this->hitCounts());
        $this->assertNull($this->ban());
    }

    #[Test]
    public function when_disabled_no_redis_connection_is_made_and_no_repository_is_resolved(): void
    {
        config(['fail2ban.enabled' => false]);

        // 有封禁也不拦：总开关关闭时连封禁键都不读
        $this->bans()->banManually(Visitor::key(self::IP), ['incident' => 'BAN-20261107-AAAAAA', 'operator' => 't'], 10);
        $this->setMode('block');

        $proxy = $this->proxyFail2BanRedis();

        try {
            $resolved = [];
            foreach ([BanRepository::class, \Maximus\Fail2Ban\Enforcer::class, \Maximus\Fail2Ban\Inspector::class] as $abstract) {
                $this->app->resolving($abstract, function () use (&$resolved, $abstract) {
                    $resolved[] = $abstract;
                });
            }

            $this->api('/ok')->assertOk();
            $this->api('/_ignition/execute-solution')->assertNotFound();
            $this->api('/ok', ['User-Agent' => 'sqlmap/1.7'])->assertOk();

            $this->assertSame(0, $proxy->connections());
            $this->assertSame(0, $proxy->trips());
            $this->assertSame([], $resolved);
            $this->assertSame(2, static::$controllerRuns);
        } finally {
            \Illuminate\Support\Facades\Redis::purge('fail2ban');
            $proxy->stop();
        }
    }

    #[Test]
    public function mode_off_neither_inspects_nor_bans_nor_blocks(): void
    {
        $this->setMode('off');

        $this->api('/_ignition/execute-solution')->assertNotFound();
        $this->api('/.env')->assertNotFound();
        $this->api('/ok', ['User-Agent' => 'sqlmap/1.7'])->assertOk();

        $this->assertSame([], $this->hitCounts());
        $this->assertNull($this->ban());
        $this->assertSame([], $this->incidents());

        // 已有的封禁也不拦，也不计被拦次数
        $this->bans()->banManually(Visitor::key(self::IP), ['incident' => 'BAN-20261107-AAAAAA', 'operator' => 't'], 10);

        $before = static::$controllerRuns;
        $this->api('/ok')->assertOk();
        $this->assertSame($before + 1, static::$controllerRuns);
        $this->assertSame(0, $this->ban()['blocked']);
    }

    /**
     * 响应里与本包无关、每次都可能变的部分（Date）去掉之后的样子。
     */
    private function snapshot($response): array
    {
        $headers = $response->headers->all();
        unset($headers['date']);
        ksort($headers);

        return [$response->getStatusCode(), $headers, $response->getContent()];
    }
}
