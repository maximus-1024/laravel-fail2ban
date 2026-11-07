<?php

namespace Maximus\Fail2Ban\Tests\Feature\Middleware;

use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Log;
use Maximus\Fail2Ban\Contracts\AllowlistRepository;
use Maximus\Fail2Ban\Events\BanSkipped;
use Maximus\Fail2Ban\Events\IpBanned;
use Maximus\Fail2Ban\Fail2Ban;
use Maximus\Fail2Ban\Visitor;
use PHPUnit\Framework\Attributes\Test;

/**
 * 端到端的封禁流程：达到次数 → 白名单 / 豁免 → 封禁 → 事件 → 拦截。
 */
class BanFlowTest extends MiddlewareTestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        Event::fake([IpBanned::class, BanSkipped::class]);
    }


    #[Test]
    public function reaching_the_count_bans_and_the_next_request_is_rejected_before_routing(): void
    {
        $this->setMode('block');

        // 404 扫描：默认 5 分钟内 10 个不同路径。差一次时不封。
        for ($i = 1; $i <= 9; $i++) {
            $this->api("/scan-{$i}")->assertNotFound();
        }

        $this->assertSame(['not-found-scan' => 9], $this->hitCounts());
        $this->assertNull($this->ban());

        $runs = static::$controllerRuns;
        $this->api('/ok')->assertOk();
        $this->assertSame($runs + 1, static::$controllerRuns);

        // 第 10 个：这次请求本身照常返回（检测在响应之后），之后的请求被拒绝
        $this->api('/scan-10')->assertNotFound();
        $this->assertNotNull($ban = $this->ban());
        $this->assertSame('not-found-scan', $ban['rule']);
        $this->assertSame(10, $ban['count']);
        $this->assertSame(30, $ban['ban_minutes']);

        $runs = static::$controllerRuns;
        $this->api('/ok')->assertForbidden();
        $this->api('/items/1', [], self::IP, 'PUT')->assertForbidden();
        $this->assertSame($runs, static::$controllerRuns, 'the controller must not run for a banned visitor');

        // 别的访客不受影响
        $this->api('/ok', [], self::OTHER_IP)->assertOk();
        $this->assertSame($runs + 1, static::$controllerRuns);
    }


    #[Test]
    public function ordinary_traffic_leaves_no_hit_records(): void
    {
        $this->setMode('block');

        $this->api('/ok')->assertOk();
        $this->api('/orders/404')->assertOk();                       // 业务层「订单不存在」
        $this->api('/boom')->assertStatus(500);                      // 系统错误
        $this->api('/items/1', [], self::IP, 'PUT')->assertOk();
        $this->api('/items/1', [], self::IP, 'DELETE')->assertOk();
        $this->api('/ok', ['User-Agent' => 'curl/8.5.0'])->assertOk();
        $this->api('/ok', ['User-Agent' => 'GuzzleHttp/7'])->assertOk();
        $this->api('/ok', ['User-Agent' => 'okhttp/4.12.0'])->assertOk();
        $this->api('/ok', ['User-Agent' => 'python-requests/2.31'])->assertOk();
        $this->api('/ok', ['User-Agent' => ''])->assertOk();
        $this->api('/ok?notify_url=https%3A%2F%2Fmerchant.example.com%2Fcallback%3Fa%3D1')->assertOk();

        $this->assertSame([], $this->hitCounts());
        $this->assertNull($this->ban());
        $this->assertSame([], $this->incidents());
        Event::assertNothingDispatched();
    }


    #[Test]
    public function allowlisted_visitors_are_never_recorded_or_banned(): void
    {
        $this->setMode('block');
        $this->app->make(AllowlistRepository::class)->add('203.0.113.0/24', null, 'test');

        $this->api('/_ignition/execute-solution')->assertNotFound();
        $this->api('/.env')->assertNotFound();
        $this->api('/ok', ['User-Agent' => 'sqlmap/1.7'])->assertOk();
        $this->api('/ok', ['User-Agent' => 'sqlmap/1.7'])->assertOk();

        $this->assertSame([], $this->hitCounts());
        $this->assertNull($this->ban());
        $this->api('/ok')->assertOk();
        Event::assertNothingDispatched();
    }

    #[Test]
    public function a_visitor_in_a_private_range_is_not_banned_and_a_warning_is_logged(): void
    {
        $this->setMode('block');
        Log::spy();

        $this->api('/_ignition/execute-solution', [], '10.1.2.3')->assertNotFound();
        $this->api('/ok', [], '10.1.2.3')->assertOk();

        $this->assertNull($this->ban('10.1.2.3'));
        $this->assertSame([], $this->hitCounts('10.1.2.3'));
        Log::shouldHaveReceived('warning')->withArgs(fn ($message, $context = []) => str_contains($message, '不是真实访客')
            && $context['source'] === 'private')->once();
    }

    #[Test]
    public function normal_requests_from_a_private_range_log_nothing(): void
    {
        Log::spy();

        $this->api('/ok', [], '10.1.2.3')->assertOk();

        Log::shouldNotHaveReceived('warning');
        $this->assertSame(1, static::$controllerRuns);
    }

    #[Test]
    public function exempted_visitors_are_not_banned_but_get_one_incident_and_one_event_per_window(): void
    {
        $this->setMode('block');
        $asked = [];
        Fail2Ban::exemptUsing(function (string $ip, $request) use (&$asked) {
            $asked[] = [$ip, $request?->getPathInfo()];

            return $ip === self::IP;
        });

        $this->api('/_ignition/execute-solution')->assertNotFound();
        $this->api('/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php')->assertNotFound();
        $this->api('/ok')->assertOk();

        $this->assertNull($this->ban());
        $this->assertSame(['known-exploit' => 2], $this->hitCounts());
        $this->assertSame(self::IP, $asked[0][0]);
        $this->assertSame('/_ignition/execute-solution', $asked[0][1]);

        $incidents = $this->incidents();
        $this->assertCount(1, $incidents);
        $this->assertSame('exempted', $incidents[0]['disposition']);
        $this->assertSame('known-exploit', $incidents[0]['rule']);
        $this->assertSame(1, $incidents[0]['count']);
        $this->assertSame(self::IP, $incidents[0]['ip']);
        $this->assertFalse($incidents[0]['observe']);
        $this->assertSame('/_ignition/execute-solution', $incidents[0]['requests'][0]['path']);

        Event::assertDispatchedTimes(BanSkipped::class, 1);
        Event::assertDispatched(BanSkipped::class, fn (BanSkipped $e) => $e->incident['id'] === $incidents[0]['id']);
        Event::assertNotDispatched(IpBanned::class);

        // 不再豁免：已经达到次数，下一次命中（哪怕是记过的同一个地址）就封
        Fail2Ban::flush();
        $this->api('/_ignition/execute-solution')->assertNotFound();
        $this->assertNotNull($this->ban());
        $this->api('/ok')->assertForbidden();
    }

    #[Test]
    public function a_long_user_agent_is_truncated_once_by_the_stores(): void
    {
        $long = 'Mozilla/5.0 '.str_repeat('x', 500);

        // 观察动作：只写「仅记录」事件（Enforcer::recordIncident 的路径）
        $this->setRule('known-exploit', ['action' => 'observe']);
        $this->api('/_ignition/execute-solution', ['User-Agent' => $long])->assertNotFound();
        $this->assertSame(substr($long, 0, 255), $this->incidents()[0]['user_agent']);

        // 封禁动作：攻击者信息与封禁事件（Enforcer::ban 的路径）
        $this->setRule('known-exploit', ['action' => 'ban']);
        $this->api('/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php', ['User-Agent' => $long])->assertNotFound();
        $this->assertSame(substr($long, 0, 255), $this->ban()['user_agent']);
        $this->assertSame(substr($long, 0, 255), $this->incidents()[0]['user_agent']);
    }


    #[Test]
    public function observe_mode_bans_and_records_but_never_blocks(): void
    {
        // 默认模式就是观察
        $this->assertSame('observe', $this->settings()->all()['mode']);

        $this->api('/_ignition/execute-solution', ['User-Agent' => 'Mozilla/5.0 test', 'CF-IPCountry' => 'NL'])->assertNotFound();

        $ban = $this->ban();
        $this->assertNotNull($ban);
        $this->assertTrue($ban['observe']);
        $this->assertSame(self::IP, $ban['ip']);
        $this->assertSame('NL', $ban['region']);
        $this->assertSame('Mozilla/5.0 test', $ban['user_agent']);
        $this->assertSame('known-exploit', $ban['rule']);

        $incidents = $this->incidents();
        $this->assertCount(1, $incidents);
        $this->assertSame('banned', $incidents[0]['disposition']);
        $this->assertSame('Mozilla/5.0 test', $incidents[0]['user_agent']);
        $this->assertTrue($incidents[0]['observe']);
        $this->assertSame($ban['incident'], $incidents[0]['id']);
        Event::assertDispatched(IpBanned::class, fn (IpBanned $e) => $e->ban['observe'] === true && $e->incident['observe'] === true);

        // 不拦，控制器照常执行；每次记一次「本应拦截」，不再检测、不再记命中
        $runs = static::$controllerRuns;
        $this->api('/ok')->assertOk();
        $this->api('/ok', ['User-Agent' => 'sqlmap/1.7'])->assertOk();
        $this->api('/.env')->assertNotFound();
        $this->assertSame($runs + 2, static::$controllerRuns);

        $this->assertSame(3, $this->ban()['blocked']);
        $this->assertSame([], $this->hitCounts());
        $this->assertCount(1, $this->incidents());
        $this->assertSame(3, $this->app->make(\Maximus\Fail2Ban\Contracts\StatsRepository::class)->trend(1)[0]['blocked']);
    }


    #[Test]
    public function each_ban_has_exactly_one_event_and_one_incident(): void
    {
        $this->setMode('block');
        $this->setRule('scanner-agent', ['count' => 1]);

        // 一个请求同时让两条规则达到次数（已知漏洞探测 + 扫描器特征）：只封一次
        $this->api('/_ignition/execute-solution', ['User-Agent' => 'sqlmap/1.7'])->assertNotFound();

        Event::assertDispatchedTimes(IpBanned::class, 1);
        $this->assertCount(1, $this->incidents());
        $this->assertSame(1, $this->app->make(\Maximus\Fail2Ban\Contracts\StatsRepository::class)->trend(1)[0]['bans']);

        // 封禁期间再来多少请求都不再产生事件
        for ($i = 0; $i < 5; $i++) {
            $this->api('/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php', ['User-Agent' => 'sqlmap/1.7'])->assertForbidden();
        }

        Event::assertDispatchedTimes(IpBanned::class, 1);
        $this->assertCount(1, $this->incidents());
        $this->assertSame(5, $this->ban()['blocked']);
        $this->assertSame(5, $this->app->make(\Maximus\Fail2Ban\Contracts\StatsRepository::class)->trend(1)[0]['blocked']);
        Event::assertDispatched(IpBanned::class, function (IpBanned $e) {
            return $e->ban['visitor'] === self::IP
                && $e->ban['rule'] === 'known-exploit'
                && $e->incident['id'] === $e->ban['incident']
                && $e->incident['disposition'] === 'banned';
        });
    }

    #[Test]
    public function when_a_parallel_request_banned_first_nothing_more_happens(): void
    {
        $this->setMode('block');
        $this->setRule('scanner-agent', ['count' => 1]);

        // 进入时还没被封；业务执行期间另一个进程先把它封了（模拟并发）
        static::$probe = fn () => $this->bans()->ban(Visitor::key(self::IP), [
            'incident' => 'BAN-20261107-PARALL', 'rule' => 'not-found-scan',
        ], 30, $this->settings()->all()['repeat']);

        $this->api('/ok', ['User-Agent' => 'sqlmap/1.7'])->assertOk();

        // 收尾时存储层返回 null：不写事件、不发 IpBanned、不计封禁数、不改那次封禁
        Event::assertNotDispatched(IpBanned::class);
        $this->assertSame([], $this->incidents());
        $this->assertSame(0, $this->app->make(\Maximus\Fail2Ban\Contracts\StatsRepository::class)->trend(1)[0]['bans']);
        $this->assertSame('BAN-20261107-PARALL', $this->ban()['incident']);
        $this->assertSame('not-found-scan', $this->ban()['rule']);
    }

    #[Test]
    public function requests_during_a_ban_do_not_extend_it(): void
    {
        $this->setMode('block');

        $this->api('/_ignition/execute-solution')->assertNotFound();
        $ban = $this->ban();
        $key = 'fail2ban:ban:'.Visitor::key(self::IP);
        $ttl = $this->redis()->pttl($key);

        usleep(50000);

        for ($i = 0; $i < 3; $i++) {
            $this->api('/_ignition/execute-solution')->assertForbidden();
            $this->api('/ok')->assertForbidden();
        }

        $this->assertSame($ban['unban_at'], $this->ban()['unban_at']);
        $this->assertSame($ban['incident'], $this->ban()['incident']);
        $this->assertLessThan($ttl, $this->redis()->pttl($key));
        $this->assertSame([], $this->hitCounts());
    }


    #[Test]
    public function an_observe_action_rule_records_once_per_window_and_never_bans(): void
    {
        $this->setMode('block');
        $this->setRule('scanner-agent', ['action' => 'observe', 'count' => 2]);

        for ($i = 0; $i < 4; $i++) {
            $this->api('/ok', ['User-Agent' => 'sqlmap/1.7'])->assertOk();
        }

        $this->assertNull($this->ban());
        $this->assertSame(['scanner-agent' => 4], $this->hitCounts());

        $incidents = $this->incidents();
        $this->assertCount(1, $incidents);
        $this->assertSame('recorded', $incidents[0]['disposition']);
        $this->assertSame('scanner-agent', $incidents[0]['rule']);
        $this->assertSame(2, $incidents[0]['count']);
        $this->assertCount(2, $incidents[0]['requests']);
        Event::assertNothingDispatched();

        // 改设置后下一个请求起生效：改成封禁
        $this->setRule('scanner-agent', ['action' => 'ban']);
        $this->api('/ok', ['User-Agent' => 'sqlmap/1.7'])->assertOk();
        $this->assertSame('scanner-agent', $this->ban()['rule']);
        $this->api('/ok')->assertForbidden();
    }

    #[Test]
    public function an_off_action_rule_is_not_inspected_and_settings_apply_from_the_next_request(): void
    {
        $this->setMode('block');
        $this->setRule('scanner-agent', ['action' => 'off']);

        $this->api('/ok', ['User-Agent' => 'sqlmap/1.7'])->assertOk();
        $this->api('/ok', ['User-Agent' => 'nikto'])->assertOk();
        $this->assertSame([], $this->hitCounts());

        // 出现次数从 2 改为 3、再打开：第 2 次不封，第 3 次封
        $this->setRule('scanner-agent', ['action' => 'ban', 'count' => 3, 'ban' => 7]);
        $this->api('/ok', ['User-Agent' => 'sqlmap/1.7'])->assertOk();
        $this->api('/ok', ['User-Agent' => 'sqlmap/1.7'])->assertOk();
        $this->assertNull($this->ban());
        $this->api('/ok', ['User-Agent' => 'sqlmap/1.7'])->assertOk();
        $this->assertSame(7, $this->ban()['ban_minutes']);
    }


    #[Test]
    public function a_request_matching_several_path_rules_counts_only_for_the_first(): void
    {
        // Ignition 地址既在已知漏洞清单里，也是 404（404 扫描），只记已知漏洞探测
        $this->setRule('known-exploit', ['count' => 5]);

        $this->api('/_ignition/execute-solution')->assertNotFound();
        $this->assertSame(['known-exploit' => 1], $this->hitCounts());

        // .env 既是敏感文件也是 404：只记敏感文件探测
        $this->api('/.env')->assertNotFound();
        $this->assertSame(['known-exploit' => 1, 'sensitive-path' => 1], $this->sorted($this->hitCounts()));
    }

    #[Test]
    public function every_rule_one_short_is_not_banned_and_rules_do_not_count_for_each_other(): void
    {
        $this->setMode('block');
        foreach (['not-found-scan', 'sensitive-path', 'scanner-agent', 'attack-pattern', 'known-exploit'] as $rule) {
            $this->setRule($rule, ['count' => 3]);
        }

        $this->api('/scan-a')->assertNotFound();
        $this->api('/scan-b')->assertNotFound();
        $this->api('/.env')->assertNotFound();
        $this->api('/.git/config')->assertNotFound();
        $this->api('/_ignition/execute-solution')->assertNotFound();
        $this->api('/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php')->assertNotFound();
        $this->api('/ok', ['User-Agent' => 'sqlmap/1.7'])->assertOk();
        $this->api('/ok', ['User-Agent' => 'sqlmap/1.7'])->assertOk();
        $this->api('/ok?q=1%20UnIoN%20SeLeCt%201')->assertOk();
        $this->api('/ok?q=2%20UnIoN%20SeLeCt%202')->assertOk();

        $this->assertSame([
            'attack-pattern' => 2,
            'known-exploit' => 2,
            'not-found-scan' => 2,
            'scanner-agent' => 2,
            'sensitive-path' => 2,
        ], $this->sorted($this->hitCounts()));
        $this->assertNull($this->ban());

        $runs = static::$controllerRuns;
        $this->api('/ok')->assertOk();
        $this->assertSame($runs + 1, static::$controllerRuns);

        // 再来一次敏感文件：只有它的次数加一，到 3 才封
        $this->api('/.htpasswd')->assertNotFound();
        $this->assertSame('sensitive-path', $this->ban()['rule']);
        $this->assertSame(3, $this->ban()['count']);
        $this->assertSame(['attack-pattern' => 2, 'known-exploit' => 2, 'not-found-scan' => 2, 'scanner-agent' => 2], $this->sorted($this->ban()['other_rules']));
    }

    #[Test]
    public function a_rule_with_count_one_bans_on_the_first_hit(): void
    {
        $this->setMode('block');

        $this->api('/_ignition/execute-solution')->assertNotFound();

        $runs = static::$controllerRuns;
        $this->api('/ok')->assertForbidden();
        $this->assertSame($runs, static::$controllerRuns);
        $this->assertSame('known-exploit', $this->ban()['rule']);
        $this->assertSame(120, $this->ban()['ban_minutes']);
    }

    private function sorted(array $counts): array
    {
        ksort($counts);

        return $counts;
    }
}
