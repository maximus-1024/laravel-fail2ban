<?php

namespace Maximus\Fail2Ban\Tests\Support;

use Illuminate\Support\Facades\Redis;
use Maximus\Fail2Ban\Fail2BanServiceProvider;

/**
 * 连真实 Redis 的测试共用的小工具。键名都不带连接前缀，由连接自己加。
 */
trait InteractsWithFail2BanRedis
{
    protected function redis()
    {
        return Redis::connection('fail2ban');
    }

    /**
     * 改专用连接的配置并重建 Redis 管理器（管理器在创建时复制配置，只 purge 不够）。
     */
    protected function reconfigureFail2BanRedis(array $config): void
    {
        Redis::purge('fail2ban');

        foreach ($config as $key => $value) {
            config(['database.redis.fail2ban.'.$key => $value]);
        }

        $this->forgetFail2BanRedis();
    }

    /**
     * 在测试进程与测试 Redis 之间夹一个往返计数的转发器，并把专用连接改连它。
     *
     * 读超时放宽到 2 秒：转发器是另一个 PHP 进程，机器忙时可能停顿，这里数的是往返不是超时。
     */
    protected function proxyFail2BanRedis(): RedisRoundTrips
    {
        $proxy = RedisRoundTrips::toTestRedis();

        $this->reconfigureFail2BanRedis(['host' => '127.0.0.1', 'port' => $proxy->port, 'timeout' => 2, 'read_timeout' => 2]);

        return $proxy;
    }

    /**
     * php-fpm 的下一个请求：Redis 管理器、连接对象与仓库都是新的（不 close，持久连接留在 phpredis 的连接池里，
     * 非持久连接随对象销毁而断开）。
     */
    protected function nextRequest(): void
    {
        $this->forgetFail2BanRedis();

        gc_collect_cycles();
    }

    /**
     * 丢掉已解析的 Redis 管理器与六个存储仓库，让它们下次用到时按当前配置重建。
     */
    protected function forgetFail2BanRedis(): void
    {
        $this->app->forgetInstance('redis');
        $this->app->forgetInstance('redis.connection');
        Redis::clearResolvedInstance('redis');

        foreach ($this->repositoryContracts() as $contract) {
            $this->app->forgetInstance($contract);
        }
    }

    /**
     * 六个存储契约（服务提供者绑定的那份清单）。
     *
     * @return list<class-string>
     */
    protected function repositoryContracts(): array
    {
        return array_keys((new Fail2BanServiceProvider($this->app))->serviceBindings);
    }

    /**
     * 让一个键真的到期（PEXPIRE 1 毫秒后稍等），而不是直接删掉。
     */
    protected function expireNow(string ...$keys): void
    {
        foreach ($keys as $key) {
            $this->redis()->pexpire($key, 1);
        }

        usleep(20000);
    }

    /**
     * 直接用不带前缀的客户端看一个完整键名是否存在。
     */
    protected function existsRaw(string $fullKey): bool
    {
        $client = $this->redis()->client();
        $prefix = $client->getOption(\Redis::OPT_PREFIX);

        $client->setOption(\Redis::OPT_PREFIX, '');

        try {
            return (bool) $client->exists($fullKey);
        } finally {
            $client->setOption(\Redis::OPT_PREFIX, $prefix);
        }
    }
}
