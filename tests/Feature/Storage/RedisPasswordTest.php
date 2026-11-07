<?php

namespace Maximus\Fail2Ban\Tests\Feature\Storage;

use Illuminate\Support\Facades\Redis;
use Maximus\Fail2Ban\Fail2Ban;
use Maximus\Fail2Ban\Tests\Feature\Middleware\MiddlewareTestCase;
use Maximus\Fail2Ban\Tests\Support\RedisRoundTrips;
use PHPUnit\Framework\Attributes\Test;

/**
 * 基础连接带密码时，Laravel 的连接器不再在每个请求里单独发一次 AUTH。
 *
 * Laravel 的 phpredis 连接器看到 password 就在每次建客户端时调用 auth()（持久连接从池里取出来也一样），
 * 正常请求因此多一次 AUTH 往返。Fail2Ban::use() 把用户名与密码放进连接的 context.auth，交给 phpredis 处理。
 *
 * 实测（phpredis 6.3）：phpredis 从持久连接池取连接做存活检查时，凭据存在就把 AUTH 与 ECHO 一起发
 * （一次往返）；关掉 redis.pconnect.echo_check_liveness 后仍单独发 AUTH。所以带密码时正常请求是 2 次往返：
 * 默认设置下比修改前少 1 次（3 → 2，与不带密码时相同）；关掉存活检查时与修改前相同（2 → 2），
 * 比不带密码时多 1 次。
 *
 * 往返测试需要一个带密码的 Redis：环境变量 FAIL2BAN_TEST_REDIS_AUTH_HOST（端口
 * FAIL2BAN_TEST_REDIS_AUTH_PORT，默认 6379）与 FAIL2BAN_TEST_REDIS_AUTH_PASSWORD。没有设置时只跑不连 Redis 的配置测试。
 */
class RedisPasswordTest extends MiddlewareTestCase
{
    protected static ?array $base = null;

    protected function setUp(): void
    {
        if (! env('FAIL2BAN_TEST_REDIS_AUTH_HOST') && $this->name() !== 'the_password_goes_into_the_connection_context') {
            $this->markTestSkipped('没有带密码的测试 Redis（FAIL2BAN_TEST_REDIS_AUTH_HOST）。');
        }

        parent::setUp();
    }

    protected function tearDown(): void
    {
        static::$base = null;
        ini_restore('redis.pconnect.echo_check_liveness');

        parent::tearDown();
    }

    protected function resolveApplicationConfiguration($app)
    {
        parent::resolveApplicationConfiguration($app);

        $app['config']->set('database.redis.client', 'phpredis');
        $app['config']->set('database.redis.options', ['cluster' => 'redis', 'prefix' => static::REDIS_PREFIX, 'persistent' => false]);
        $app['config']->set('database.redis.default', static::$base ?? [
            'host' => env('FAIL2BAN_TEST_REDIS_AUTH_HOST', env('FAIL2BAN_TEST_REDIS_HOST', '127.0.0.1')),
            'port' => (string) env('FAIL2BAN_TEST_REDIS_AUTH_PORT', 6379),
            'username' => null,
            'password' => env('FAIL2BAN_TEST_REDIS_AUTH_HOST') ? env('FAIL2BAN_TEST_REDIS_AUTH_PASSWORD') : null,
            'database' => '0',
        ]);
        $app['config']->set('fail2ban.redis', ['connection' => 'fail2ban', 'use' => 'default', 'database' => null, 'timeout' => 2]);
    }

    protected function defineFail2BanRedis($app): void
    {
    }

    #[Test]
    public function the_password_goes_into_the_connection_context(): void
    {
        foreach ([
            'password only' => [['password' => 'secret'], 'secret'],
            'username and password' => [['username' => 'fw', 'password' => 'secret'], ['fw', 'secret']],
            'url' => [['url' => 'tcp://fw:secret@redis.internal:6390'], ['fw', 'secret']],
            'keeps other context' => [['password' => 'secret', 'context' => ['stream' => ['verify_peer' => false]]], 'secret'],
        ] as $label => [$base, $auth]) {
            config(['database.redis.fail2ban' => null, 'database.redis.withpw' => $base + ['host' => 'redis.internal', 'port' => 6379]]);

            Fail2Ban::use('withpw');

            $config = config('database.redis.fail2ban');
            $this->assertSame($auth, $config['context']['auth'], $label);
            $this->assertArrayNotHasKey('password', $config, $label.'：留在 password 上连接器每次都会 AUTH');
            $this->assertArrayNotHasKey('username', $config, $label);

            if (isset($base['context'])) {
                $this->assertSame(['verify_peer' => false], $config['context']['stream'], $label);
            }
        }

        // 没有密码时不加 context
        config(['database.redis.fail2ban' => null, 'database.redis.nopw' => ['host' => 'redis.internal', 'port' => 6379, 'password' => null]]);
        Fail2Ban::use('nopw');
        $this->assertArrayNotHasKey('context', config('database.redis.fail2ban'));
    }

    #[Test]
    public function a_normal_request_does_not_send_a_separate_auth_on_a_pooled_connection(): void
    {
        $proxy = new RedisRoundTrips((string) env('FAIL2BAN_TEST_REDIS_AUTH_HOST'), (int) env('FAIL2BAN_TEST_REDIS_AUTH_PORT', 6379));

        try {
            $result = [];

            foreach ([
                'password' => ['password' => env('FAIL2BAN_TEST_REDIS_AUTH_PASSWORD')],
                'username and password' => ['username' => 'default', 'password' => env('FAIL2BAN_TEST_REDIS_AUTH_PASSWORD')],
            ] as $label => $credentials) {
                static::$base = ['host' => '127.0.0.1', 'port' => $proxy->port, 'database' => '0'] + $credentials;
                $this->refreshApplication();
                $this->setMode('block');

                foreach (['1' => 'ECHO on', '0' => 'echo_check_liveness=0'] as $echo => $name) {
                    ini_set('redis.pconnect.echo_check_liveness', (string) $echo);

                    $this->nextRequest();
                    $this->normalRequest(); // 第一个请求建连接（这里认证一次）

                    $connections = $proxy->connections();
                    $trips = $proxy->trips();

                    for ($i = 0; $i < 10; $i++) {
                        $this->nextRequest();
                        $this->normalRequest();
                    }

                    $result["{$label}, {$name}"] = [
                        'connections' => ($proxy->connections() - $connections) / 10,
                        'trips' => ($proxy->trips() - $trips) / 10,
                    ];
                }

                Redis::purge('fail2ban');
            }

            fwrite(STDERR, 'normal request with a password: '.json_encode($result, JSON_UNESCAPED_UNICODE)."\n");

            // 修改前：ECHO on 3 次（存活检查 ECHO、Laravel 的 AUTH、读取），关掉存活检查 2 次
            $this->assertEquals([
                'password, ECHO on' => ['connections' => 0, 'trips' => 2],
                'password, echo_check_liveness=0' => ['connections' => 0, 'trips' => 2],
                'username and password, ECHO on' => ['connections' => 0, 'trips' => 2],
                'username and password, echo_check_liveness=0' => ['connections' => 0, 'trips' => 2],
            ], $result);
        } finally {
            Redis::purge('fail2ban');
            $proxy->stop();
        }
    }
}
