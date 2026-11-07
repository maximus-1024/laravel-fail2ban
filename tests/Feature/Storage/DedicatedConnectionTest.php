<?php

namespace Maximus\Fail2Ban\Tests\Feature\Storage;

use Illuminate\Support\Facades\Redis;
use Maximus\Fail2Ban\Contracts\SettingsRepository;
use Maximus\Fail2Ban\Fail2Ban;
use Maximus\Fail2Ban\Http\Middleware\BlockBannedIps;
use Maximus\Fail2Ban\Inspector;
use Maximus\Fail2Ban\Tests\Feature\Middleware\MiddlewareTestCase;
use Maximus\Fail2Ban\Tests\Support\RedisRoundTrips;
use PHPUnit\Framework\Attributes\Test;

/**
 * 专用 Redis 连接由扩展包在注册阶段定义（Fail2Ban::use()，照 Horizon::use()）。
 *
 * 这里的宿主像 Laravel 12 的默认配置：只有 default 连接（带 database、重试与退避），
 * 全局 options 里 persistent 为 false、有全局键前缀，没有 fail2ban 连接。
 */
class DedicatedConnectionTest extends MiddlewareTestCase
{
    /**
     * default 连接指向哪里（往返测试换成转发器）。
     */
    protected static ?array $base = null;

    /**
     * 宿主的 config/database.php 与 config/fail2ban.php：在服务提供者注册之前就已加载
     * （Testbench 的 defineEnvironment() 在注册之后才执行，所以写在这里）。
     */
    protected function resolveApplicationConfiguration($app)
    {
        parent::resolveApplicationConfiguration($app);

        $app['config']->set('database.redis.client', 'phpredis');

        $app['config']->set('database.redis.options', [
            'cluster' => 'redis',
            'prefix' => static::REDIS_PREFIX,
            'persistent' => false,
        ]);

        $app['config']->set('database.redis.default', static::$base ?? [
            'url' => null,
            'host' => env('FAIL2BAN_TEST_REDIS_HOST', '127.0.0.1'),
            'username' => null,
            'password' => null,
            'port' => (string) env('FAIL2BAN_TEST_REDIS_PORT', 6379),
            'database' => '0',
            'max_retries' => 3,
            'backoff_algorithm' => 'decorrelated_jitter',
            'backoff_base' => 100,
            'backoff_cap' => 1000,
        ]);

        $app['config']->set('fail2ban.redis', [
            'connection' => 'fail2ban',
            'use' => 'default',
            'database' => null,
            'timeout' => 0.35,
        ]);
    }

    /**
     * 宿主没有定义专用连接。
     */
    protected function defineFail2BanRedis($app): void
    {
    }

    protected function tearDown(): void
    {
        static::$base = null;
        ini_restore('redis.pconnect.echo_check_liveness');

        parent::tearDown();
    }

    #[Test]
    public function the_provider_defines_a_persistent_connection_without_database_from_the_base_connection(): void
    {
        $config = config('database.redis.fail2ban');

        $this->assertIsArray($config, '宿主没定义时扩展包应定义专用连接');
        $this->assertSame(env('FAIL2BAN_TEST_REDIS_HOST', '127.0.0.1'), $config['host']);
        $this->assertArrayNotHasKey('database', $config, '带 database 键 Laravel 每次取连接都会发 SELECT');
        $this->assertArrayNotHasKey('persistent', $config, '写在顶层会被全局 options.persistent 盖掉');
        $this->assertTrue($config['options']['persistent']);
        $this->assertSame(Fail2Ban::PERSISTENT_ID, $config['options']['persistent_id']);
        $this->assertSame(0.35, $config['options']['timeout']);
        $this->assertSame(0.35, $config['options']['read_timeout']);
        $this->assertSame(0, $config['options']['max_retries']);

        // 基础连接本身不变
        $this->assertSame('0', config('database.redis.default.database'));
    }

    #[Test]
    public function the_defined_connection_is_really_persistent_with_the_timeouts_and_the_global_prefix(): void
    {
        $client = Redis::connection('fail2ban')->client();

        $this->assertSame(Fail2Ban::PERSISTENT_ID, $client->getPersistentID());
        $this->assertEqualsWithDelta(0.35, $client->getTimeout(), 0.0001);
        $this->assertEqualsWithDelta(0.35, $client->getReadTimeout(), 0.0001);
        $this->assertSame(0, $client->getOption(\Redis::OPT_MAX_RETRIES));
        $this->assertSame(static::REDIS_PREFIX, $client->getOption(\Redis::OPT_PREFIX), '全局键前缀照常生效');
        $this->assertSame(0, $client->getDbNum());

        // 存储层照常可用，键带全局前缀
        $this->app->make(SettingsRepository::class)->save(['mode' => 'block'], 'test');
        $client->setOption(\Redis::OPT_PREFIX, '');
        $this->assertSame(1, $client->exists(static::REDIS_PREFIX.'fail2ban:settings'));
        $client->setOption(\Redis::OPT_PREFIX, static::REDIS_PREFIX);
    }

    #[Test]
    public function a_connection_the_host_already_defined_is_used_as_is(): void
    {
        $hosts = [
            'host' => 'redis.internal', 'port' => 6380, 'database' => 7, 'persistent' => false, 'options' => ['prefix' => 'mine:'],
        ];

        config(['database.redis.fail2ban' => $hosts]);
        Fail2Ban::use('default');
        $this->assertSame($hosts, config('database.redis.fail2ban'));

        // 宿主把专用连接名指向自己的已有连接（例如 FAIL2BAN_REDIS_CONNECTION=default）
        config(['fail2ban.redis.connection' => 'default']);
        $default = config('database.redis.default');
        Fail2Ban::use('default');
        $this->assertSame($default, config('database.redis.default'));

        // 基础连接不存在：什么都不定义，也不抛异常（用到时按读取失败放行）
        config(['fail2ban.redis.connection' => 'fail2ban', 'database.redis.fail2ban' => null]);
        Fail2Ban::use('missing');
        $this->assertNull(config('database.redis.fail2ban'));
    }

    #[Test]
    public function an_explicit_database_and_a_url_are_honoured(): void
    {
        config([
            'database.redis.fail2ban' => null,
            'database.redis.queue' => ['url' => 'tcp://:secret@redis.internal:6390/4', 'database' => 2],
            'fail2ban.redis.database' => '3',
        ]);

        Fail2Ban::use('queue');

        $config = config('database.redis.fail2ban');
        $this->assertSame('redis.internal', $config['host']);
        $this->assertSame(6390, $config['port']);
        $this->assertSame('secret', $config['context']['auth'], '密码放进 context.auth，只在新建连接时认证');
        $this->assertArrayNotHasKey('password', $config);
        $this->assertSame(3, $config['database'], '只有显式指定库号时才带 database');
        $this->assertArrayNotHasKey('url', $config);
    }

    #[Test]
    public function registering_and_booting_the_provider_does_not_touch_redis(): void
    {
        $proxy = RedisRoundTrips::toTestRedis();

        try {
            static::$base = ['host' => '127.0.0.1', 'port' => $proxy->port, 'database' => '0'];

            $this->refreshApplication();

            foreach ([...$this->repositoryContracts(), Inspector::class, BlockBannedIps::class] as $abstract) {
                $this->app->make($abstract);
            }

            $this->assertTrue(config('database.redis.fail2ban.options.persistent'));
            $this->assertSame(0, $proxy->connections());
            $this->assertSame(0, $proxy->trips());
        } finally {
            Redis::purge('fail2ban');
            $proxy->stop();
        }
    }

    /**
     * 模拟 php-fpm 的请求边界（丢掉 Redis 管理器与连接对象，不 close），数正常请求真实的往返：
     *  - 不选库：没有 SELECT；
     *  - 持久连接：第二个请求起不再握手；
     *  - phpredis 从持久连接池取连接时默认先发一次 ECHO 检查存活（redis.pconnect.echo_check_liveness=1），
     *    这是 PHP 的全局设置，扩展包不改它；关掉后正常请求只剩本包那一次读取。
     *  - 显式设了 fail2ban.redis.database 时每个请求多一次 SELECT。
     */
    #[Test]
    public function a_normal_request_costs_one_read_plus_the_liveness_check_and_no_select(): void
    {
        $proxy = RedisRoundTrips::toTestRedis();

        try {
            static::$base = ['host' => '127.0.0.1', 'port' => $proxy->port, 'database' => '0'];
            $this->refreshApplication();
            // 转发器是另一个 PHP 进程，机器忙时会停顿；这里数的是往返不是超时
            config(['fail2ban.redis.timeout' => 2]);

            $result = [];

            foreach ([
                'default (ECHO on)' => ['1', null],
                'echo_check_liveness=0' => ['0', null],
                'fail2ban.redis.database=0' => ['1', 0],
            ] as $label => [$echo, $database]) {
                ini_set('redis.pconnect.echo_check_liveness', $echo);
                config(['database.redis.fail2ban' => null, 'fail2ban.redis.database' => $database]);
                Fail2Ban::use('default');

                $this->nextRequest();
                $this->normalRequest(); // 第一个请求建连接

                $connections = $proxy->connections();
                $trips = $proxy->trips();

                for ($i = 0; $i < 10; $i++) {
                    $this->nextRequest();
                    $this->normalRequest();
                }

                $result[$label] = [
                    'connections' => ($proxy->connections() - $connections) / 10,
                    'trips' => ($proxy->trips() - $trips) / 10,
                ];
            }

            fwrite(STDERR, '[connection] normal request across request boundaries: '.json_encode($result, JSON_UNESCAPED_UNICODE)."\n");

            $this->assertEquals(['connections' => 0, 'trips' => 2], $result['default (ECHO on)']);
            $this->assertEquals(['connections' => 0, 'trips' => 1], $result['echo_check_liveness=0']);
            $this->assertEquals(['connections' => 0, 'trips' => 3], $result['fail2ban.redis.database=0']);
        } finally {
            Redis::purge('fail2ban');
            $proxy->stop();
        }
    }
}
