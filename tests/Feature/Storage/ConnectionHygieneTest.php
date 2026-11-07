<?php

namespace Maximus\Fail2Ban\Tests\Feature\Storage;

use Illuminate\Support\Facades\Redis;
use Maximus\Fail2Ban\Contracts\AllowlistRepository;
use Maximus\Fail2Ban\Contracts\AuditRepository;
use Maximus\Fail2Ban\Contracts\BanRepository;
use Maximus\Fail2Ban\Contracts\IncidentRepository;
use Maximus\Fail2Ban\Contracts\SettingsRepository;
use Maximus\Fail2Ban\Contracts\StatsRepository;
use Maximus\Fail2Ban\Repositories\Concerns\InteractsWithRedis;
use Maximus\Fail2Ban\Tests\Support\InteractsWithFail2BanRedis;
use Maximus\Fail2Ban\Tests\TestCase;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use RedisException;
use RuntimeException;

/**
 * 宿主会把专用连接开成 phpredis 持久连接：同一个 php-fpm 进程的下一个请求复用同一条 TCP 连接。
 * 这里验证存储层不会给下一个请求留下连接状态。
 */
class ConnectionHygieneTest extends TestCase
{
    use InteractsWithFail2BanRedis;

    private const V = '203.0.113.47';

    private const W = '203.0.113.48';

    /**
     * 测试改过的 phpredis 设置及其原值。
     *
     * @var array<string, string|false>
     */
    private array $ini = [];

    protected function tearDown(): void
    {
        Redis::purge('fail2ban');

        foreach ($this->ini as $key => $value) {
            if ($value !== false) {
                ini_set($key, $value);
            }
        }

        parent::tearDown();
    }

    private function usePersistentConnection(string $id = 'fw-hygiene'): void
    {
        // 全局 database.redis.options.persistent 会盖掉连接顶层的 persistent，所以写在连接自己的 options 里
        $this->reconfigureFail2BanRedis(['options.persistent' => true, 'persistent_id' => $id.'-'.getmypid()]);

        $this->assertTrue($this->redis()->client()->getPersistentID() !== null, 'not a persistent connection');
    }

    /**
     * 另开一条原始连接让服务器忙半秒（超过测试连接的 0.2 秒读超时）。返回这条连接，读它的回复即等忙完。
     *
     * 按 os.clock()（Redis 7 起脚本里可用）忙等，而不是固定的循环次数：机器快慢不影响忙的时长，读超时总有
     * 0.3 秒的余量。不能用 TIME：脚本执行期间它返回的是脚本开始时的时间。
     *
     * @return resource
     */
    private function keepServerBusy()
    {
        $script = 'local start = os.clock() while os.clock() - start < 0.5 do end return 1';
        $socket = stream_socket_client('tcp://'.env('FAIL2BAN_TEST_REDIS_HOST', '127.0.0.1').':'.env('FAIL2BAN_TEST_REDIS_PORT', 6379));

        fwrite($socket, "*3\r\n\$4\r\nEVAL\r\n\$".strlen($script)."\r\n{$script}\r\n\$1\r\n0\r\n");
        usleep(30000);

        return $socket;
    }

    /**
     * 本测试这条连接在服务器上不在 MULTI 里、没有 WATCH、仍在配置的库上。
     *
     * 只看自己这条连接：测试 Redis 被别的测试进程共用。
     */
    private function assertNoClientHoldsState(): void
    {
        $id = (string) $this->redis()->client()->rawCommand('CLIENT', 'ID');

        $inspector = new \Redis;
        $inspector->connect(env('FAIL2BAN_TEST_REDIS_HOST', '127.0.0.1'), (int) env('FAIL2BAN_TEST_REDIS_PORT', 6379));

        $mine = array_values(array_filter($inspector->client('list'), fn ($client) => (string) $client['id'] === $id));
        $inspector->close();

        $this->assertCount(1, $mine);
        $this->assertSame('-1', (string) $mine[0]['multi'], 'the connection is inside MULTI');
        $this->assertSame('0', (string) ($mine[0]['watch'] ?? '0'), 'the connection holds WATCH');
        $this->assertSame((string) config('database.redis.fail2ban.database'), (string) $mine[0]['db'], 'the connection switched database');
    }

    #[Test]
    public function a_throwing_pipeline_callback_does_not_leave_the_client_in_pipeline_mode(): void
    {
        $repository = new class($this->app->make('redis'))
        {
            use InteractsWithRedis;

            public function __construct($redis)
            {
                $this->redis = $redis;
            }

            public function broken(): void
            {
                $this->pipeline(function ($pipe) {
                    $pipe->set('fail2ban:probe', 'from-broken-pipeline');

                    throw new RuntimeException('boom');
                });
            }
        };

        $this->redis()->set('fail2ban:probe', 'original');

        try {
            $repository->broken();
            $this->fail('No exception.');
        } catch (RuntimeException) {
        }

        $this->assertSame(\Redis::ATOMIC, $this->redis()->client()->getMode());
        $this->assertSame('original', $this->redis()->get('fail2ban:probe'));
    }

    #[Test]
    public function a_full_workflow_leaves_no_transaction_or_watch_on_the_server(): void
    {
        $this->usePersistentConnection();

        $bans = $this->app->make(BanRepository::class);
        $stats = $this->app->make(StatsRepository::class);

        $bans->lookup(self::V);
        $this->recordHit('known-exploit', self::V, '/cgi-bin/x', target: '/cgi-bin/x');
        $ban = $bans->ban(self::V, ['incident' => 'BAN-20261107-AAAAAA', 'rule' => 'known-exploit'], 120,
            ['enabled' => true, 'factor' => 2, 'max_days' => 7, 'keep_days' => 7]);
        $this->app->make(IncidentRepository::class)->record(['id' => $ban['incident'], 'disposition' => 'banned'] + $ban);
        $bans->recordBlock(self::V);
        $stats->incrementBlocked();
        $bans->banManually(self::V, ['incident' => 'BAN-20261107-BBBBBB', 'operator' => 'admin'], 5);
        $bans->all();
        $bans->unban(self::V);
        $this->app->make(IncidentRepository::class)->markUnbanned('BAN-20261107-AAAAAA');
        $this->app->make(AuditRepository::class)->record('admin', 'unban', self::V);
        $this->app->make(AllowlistRepository::class)->add('198.51.100.0/24', null, 'admin');
        $this->app->make(SettingsRepository::class)->save(['mode' => 'block'], 'admin');

        $this->assertSame(\Redis::ATOMIC, $this->redis()->client()->getMode());
        $this->assertNoClientHoldsState();
    }

    #[Test]
    public function after_a_timeout_the_next_request_on_the_persistent_connection_reads_correct_data(): void
    {
        $this->usePersistentConnection();

        $bans = $this->app->make(BanRepository::class);
        $bans->banManually(self::V, ['incident' => 'BAN-20261107-AAAAAA', 'operator' => 'admin'], 10);
        $bans->lookup(self::V);

        // 这个请求的读取超时（服务器正忙）
        $busy = $this->keepServerBusy();

        try {
            $bans->lookup(self::V);
            $this->fail('Expected a timeout.');
        } catch (RedisException) {
        }

        fgets($busy); // 等服务器忙完；迟到的回复不能被下一个请求读到
        fclose($busy);

        $this->nextRequest();
        $bans = $this->app->make(BanRepository::class);

        $result = $bans->lookup(self::V);
        $this->assertSame('BAN-20261107-AAAAAA', $result['ban']['incident']);
        $this->assertSame('observe', $result['settings']['mode']);
        $this->assertNull($bans->lookup('198.51.100.1')['ban']);
        $this->assertSame(\Redis::ATOMIC, $this->redis()->client()->getMode());

        // 同一个请求里管道读超时之后接着读（例如封禁后写攻击事件超时、接着计数）：phpredis 读脚本回复超时后
        // 不会自己断开，不处理的话下一条命令读到的是这个管道迟到的回复（进入时的读取曾读到封禁值 ":1"）。
        // InteractsWithRedis::resetClient() 在出错时关掉连接，后面的命令重连，读到的是自己的回复。
        $busy = $this->keepServerBusy();

        try {
            $this->recordHit('known-exploit', self::V, '/cgi-bin/x', target: '/cgi-bin/x');
            $this->fail('Expected a timeout.');
        } catch (RedisException) {
        }

        fgets($busy);
        fclose($busy);

        $result = $bans->lookup(self::V);
        $this->assertSame('BAN-20261107-AAAAAA', $result['ban']['incident']);
        $this->assertSame('observe', $result['settings']['mode']);
        $this->assertNoClientHoldsState();
    }

    /**
     * 出错的四类调用 × 持久连接的三种连接池设置（phpredis 默认开连接池、取出时用 ECHO 检查连接；
     * 宿主可能关掉其中之一，那时迟到的回复会留给下一个请求，或者在不开连接池时被同一个请求里的重连拿回来）。
     *
     * @return iterable<string, array{0: string, 1: array<string, string>}>
     */
    public static function failedCalls(): iterable
    {
        $pools = [
            'pooled' => [],
            'pooled without liveness check' => ['redis.pconnect.echo_check_liveness' => '0'],
            'not pooled' => ['redis.pconnect.pooling_enabled' => '0'],
        ];

        foreach (['pipeline with scripts', 'plain pipeline', 'script', 'single command'] as $call) {
            foreach ($pools as $pool => $ini) {
                yield "{$call}, {$pool}" => [$call, $ini];
            }
        }
    }

    #[Test]
    #[DataProvider('failedCalls')]
    public function after_a_timed_out_call_later_calls_in_the_same_and_the_next_request_read_their_own_replies(string $call, array $ini): void
    {
        foreach ($ini as $key => $value) {
            $this->ini[$key] = ini_set($key, $value);
        }

        $this->usePersistentConnection('fw-hygiene-'.md5($call.json_encode($ini)));

        $this->app->make(SettingsRepository::class)->save(['mode' => 'block'], 'admin');
        $this->app->make(AllowlistRepository::class)->add('192.0.2.0/24', null, 'admin');
        $bans = $this->app->make(BanRepository::class);
        $bans->banManually(self::V, ['incident' => 'BAN-20261107-AAAAAA', 'operator' => 'admin'], 10);
        $bans->banManually(self::W, ['incident' => 'BAN-20261107-BBBBBB', 'operator' => 'admin'], 10);

        $busy = $this->keepServerBusy();

        try {
            match ($call) {
                'pipeline with scripts' => $this->recordHit('known-exploit', self::V, '/a'),
                'plain pipeline' => $bans->lookup(self::V),
                'script' => $bans->recordBlock(self::V),
                'single command' => $this->app->make(AllowlistRepository::class)->match('192.0.2.5'),
            };

            $this->fail('Expected a timeout.');
        } catch (RedisException) {
        }

        fgets($busy); // 服务器忙完，超时那次调用的回复已经发出
        fclose($busy);

        $this->assertRepliesAreOwn(1);

        $this->nextRequest();

        $this->assertRepliesAreOwn(2);
        $this->assertNoClientHoldsState();
    }

    /**
     * 每类调用各来一次，结果都是自己的：第一条就是进入时的那次读取。
     */
    private function assertRepliesAreOwn(int $round): void
    {
        $result = $this->app->make(BanRepository::class)->lookup(self::W);
        $this->assertSame('BAN-20261107-BBBBBB', $result['ban']['incident'] ?? null);
        $this->assertSame('block', $result['settings']['mode']);

        $this->assertSame('block', $this->app->make(SettingsRepository::class)->all()['mode']);
        $this->assertSame('192.0.2.0/24', $this->app->make(AllowlistRepository::class)->match('192.0.2.5')['entry'] ?? null);
        $this->assertSame($round, $this->app->make(BanRepository::class)->recordBlock(self::W));
        $this->assertSame(['count' => $round, 'added' => true], $this->recordHit('known-exploit', self::W, '/b'.$round));
    }
}
