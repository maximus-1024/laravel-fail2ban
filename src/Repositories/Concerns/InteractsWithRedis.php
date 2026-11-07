<?php

namespace Maximus\Fail2Ban\Repositories\Concerns;

use Throwable;

/**
 * 六个 Redis 实现共用的连接访问。
 *
 * 约定（为了业务路径的往返最少，也为了持久连接被下一个请求复用时干净）：
 *  - 构造时不连 Redis，第一次调用方法时才通过管理器取连接；
 *  - 只用单条命令、管道（客户端缓冲，一次往返）和 Lua 脚本（一次往返、原子）；
 *  - 不用 MULTI/WATCH/SELECT：phpredis 的 MULTI 每条命令都要等一次 QUEUED，
 *    而且会在服务器上留下事务状态；
 *  - 管道或脚本出错时关掉用过的连接（resetClient()）：可能还有迟到的回复在路上，随连接一起丢掉，
 *    本请求后面的命令自动重连，拿到的是自己的回复。
 */
trait InteractsWithRedis
{
    /**
     * The Redis factory instance.
     *
     * @var \Illuminate\Contracts\Redis\Factory
     */
    public $redis;

    /**
     * Get the Redis connection instance.
     *
     * @return \Illuminate\Redis\Connections\Connection
     */
    protected function connection()
    {
        return $this->redis->connection(config('fail2ban.redis.connection'));
    }

    /**
     * 在一个管道里执行（一次往返），返回各命令的结果。
     */
    protected function pipeline(callable $callback): array
    {
        $connection = $this->connection();

        try {
            return (array) $connection->pipeline($callback);
        } catch (Throwable $e) {
            $this->resetClient($connection->client());

            throw $e;
        }
    }

    /**
     * 执行一个 Lua 脚本（一次往返）。
     *
     * @param  list<string>  $keys
     * @param  list<string|int|float>  $arguments
     */
    protected function script(string $script, array $keys, array $arguments = []): mixed
    {
        // 直接调 phpredis 客户端（参数顺序同 queueScript()），不经过 Laravel 的 command()：它在读错误后重连，
        // 但服务器还忙时重连里的 SELECT 也会超时，换不成，旧连接带着迟到的回复留在本请求里；换成了也不关旧连接，
        // 旧连接回到连接池（不开连接池时新客户端拿到的就是同一条持久连接）。出错时由 resetClient() 关掉。
        $client = $this->connection()->client();

        try {
            return $client->eval($script, [...$keys, ...$arguments], count($keys));
        } catch (Throwable $e) {
            $this->resetClient($client);

            throw $e;
        }
    }

    /**
     * 在管道里排一次 Lua 脚本调用（$pipe 是 pipeline() 回调拿到的 phpredis 客户端，参数顺序与 Laravel 的 eval() 不同）。
     *
     * @param  list<string>  $keys
     * @param  list<string|int|float>  $arguments
     */
    protected function queueScript(mixed $pipe, string $script, array $keys, array $arguments = []): void
    {
        $pipe->eval($script, [...$keys, ...$arguments], count($keys));
    }

    /**
     * 存进 Redis 的 JSON：中文与斜杠不转义；地址里可能有非法 UTF-8，替换掉而不是让编码失败。
     */
    protected function encode(mixed $value): string
    {
        return json_encode($value, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
    }

    /**
     * 管道或脚本出错之后复位客户端，不让本请求后面的命令读到不属于自己的回复。
     *
     * 命令发出去之后出的错（读超时等），服务器的回复可能还在路上。phpredis 是否自己断开取决于超时落在回复的
     * 哪一处（实测脚本回复、管道里的脚本回复都可能不断开），不断开时这条连接上的下一条命令读到的是上一次迟到的
     * 回复。所以出错一律关掉连接（持久连接也真的关掉，不放回连接池），同一个客户端对象的下一条命令自动重连
     * （重新认证、选库）。还停在管道模式里（回调里出错，命令没发出去）的先丢弃缓冲的命令。
     */
    protected function resetClient(mixed $client): void
    {
        if (! $client instanceof \Redis) {
            return;
        }

        try {
            if ($client->getMode() !== \Redis::ATOMIC) {
                $client->discard();
            }

            $client->close();
        } catch (Throwable) {
            // 关不掉说明连接已经断了：phpredis 会在下次使用时重连。
        }
    }
}
