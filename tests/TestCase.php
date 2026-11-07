<?php

namespace Maximus\Fail2Ban\Tests;

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\Redis;
use Maximus\Fail2Ban\Contracts\BanRepository;
use Maximus\Fail2Ban\Fail2Ban;
use Maximus\Fail2Ban\Fail2BanServiceProvider;
use Orchestra\Testbench\TestCase as Orchestra;

abstract class TestCase extends Orchestra
{
    /**
     * 测试专用 Redis 键前缀，避免与任何真实数据混用。
     */
    protected const REDIS_PREFIX = 'f2btest:';

    protected function setUp(): void
    {
        parent::setUp();

        Fail2Ban::flush();

        Redis::connection('fail2ban')->flushdb();
    }

    protected function tearDown(): void
    {
        Fail2Ban::flush();

        parent::tearDown();
    }

    /**
     * 记一次命中（连同命中统计），走封禁流程用的 BanRepository::recordHits()。
     *
     * @param  array{time?: int, method?: string, path?: string}  $record  缺的项按「现在、GET、去重键或 /」补上
     * @return array{count: int, added: bool}
     */
    protected function recordHit(string $rule, string $visitor, ?string $dedupe = null, array $record = [], int $window = 10, int $max = 100, ?string $target = null, ?string $region = null): array
    {
        $record += ['time' => CarbonImmutable::now()->getTimestamp(), 'method' => 'GET', 'path' => $dedupe ?? '/'];

        return app(BanRepository::class)->recordHits($visitor, [
            ['rule' => $rule, 'dedupe' => $dedupe, 'record' => $record, 'window' => $window],
        ], $max, $target, $region)[0];
    }

    protected function getPackageProviders($app): array
    {
        return [Fail2BanServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set('database.redis.client', 'phpredis');

        // Testbench 骨架目录（vendor/orchestra/testbench-core/laravel）里如果留着别的进程（例如 testbench serve）
        // 复制进去的 .env，会话驱动会变成 cookie；测试一律用内存会话，不受它影响。
        $app['config']->set('session.driver', 'array');

        $this->defineFail2BanRedis($app);
    }

    /**
     * 测试用的专用连接：像宿主自己在 config/database.php 里定义了它（扩展包原样使用，不另行定义）。
     * 非持久连接、0 号库；每个测试开始前清空这个库（phpunit 串行执行，测试之间靠这一步隔离）。
     * 要测扩展包自动定义的连接时覆盖这个方法（见 DedicatedConnectionTest）。
     */
    protected function defineFail2BanRedis($app): void
    {
        $app['config']->set('database.redis.fail2ban', [
            'host' => env('FAIL2BAN_TEST_REDIS_HOST', '127.0.0.1'),
            'port' => (int) env('FAIL2BAN_TEST_REDIS_PORT', 6379),
            'password' => null,
            'database' => 0,
            'timeout' => 0.2,
            'read_timeout' => 0.2,
            'options' => [
                'prefix' => static::REDIS_PREFIX,
            ],
        ]);
    }
}
