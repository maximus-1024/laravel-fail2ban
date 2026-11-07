<?php

namespace Maximus\Fail2Ban\Tests\Support;

use RuntimeException;

/**
 * 在测试进程旁边起一个 redis-proxy.php，数客户端与 Redis 之间的往返。
 */
class RedisRoundTrips
{
    /** @var resource */
    protected $process;

    public readonly int $port;

    protected string $file;

    public function __construct(string $host, int $port)
    {
        $this->file = tempnam(sys_get_temp_dir(), 'fw-proxy-');

        @unlink($this->file);

        $this->process = proc_open(
            [PHP_BINARY, __DIR__.'/redis-proxy.php', $host, (string) $port, $this->file],
            [1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']],
            $pipes
        );

        for ($i = 0; $i < 200 && ! is_file($this->file); $i++) {
            usleep(10000);
        }

        if (! is_file($this->file)) {
            throw new RuntimeException('Redis proxy did not start.');
        }

        $this->port = $this->read()[2];
    }

    /**
     * 转发到测试 Redis（FAIL2BAN_TEST_REDIS_HOST、FAIL2BAN_TEST_REDIS_PORT）。
     */
    public static function toTestRedis(): static
    {
        return new static((string) env('FAIL2BAN_TEST_REDIS_HOST', '127.0.0.1'), (int) env('FAIL2BAN_TEST_REDIS_PORT', 6379));
    }

    /**
     * 到目前为止的往返数。
     */
    public function trips(): int
    {
        return $this->read()[0];
    }

    /**
     * 到目前为止接受过的连接数。
     */
    public function connections(): int
    {
        return $this->read()[1];
    }

    /**
     * 执行一段代码，返回它造成的往返数。
     */
    public function count(callable $callback): int
    {
        $before = $this->trips();

        $callback();

        return $this->trips() - $before;
    }

    public function stop(): void
    {
        proc_terminate($this->process);
        proc_close($this->process);
        @unlink($this->file);
    }

    /**
     * @return array{0: int, 1: int, 2: int} 往返数、连接数、监听端口
     */
    protected function read(): array
    {
        $parts = explode(' ', (string) file_get_contents($this->file));

        return [(int) $parts[0], (int) ($parts[1] ?? 0), (int) ($parts[2] ?? 0)];
    }
}
