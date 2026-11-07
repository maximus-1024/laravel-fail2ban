<?php

namespace Maximus\Fail2Ban\Tests\Feature\Middleware;

use Maximus\Fail2Ban\Contracts\AuditRepository;
use Maximus\Fail2Ban\Operations;
use PHPUnit\Framework\Attributes\Test;

/**
 * 观察模式产生的封禁不带进拦截模式。
 *
 *  1. 观察模式下的自动封禁不计入累犯：「第几次被封」恒为 1，时长不加长，累犯记录不动；
 *  2. 运行模式切到拦截时，解除名单里观察期间产生的自动封禁（攻击事件保留，处置变为已解封），
 *     操作日志写明解除了几个。面板与命令都走 Operations::saveSettings()。
 */
class ObserveModeSwitchTest extends MiddlewareTestCase
{
    #[Test]
    public function a_visitor_banned_during_observation_is_not_blocked_after_switching_to_block_from_the_panel(): void
    {
        $this->setMode('observe');

        $this->api('/_ignition/execute-solution')->assertNotFound();
        $this->assertTrue($this->ban()['observe']);
        $incident = $this->ban()['incident'];

        $this->app->make(Operations::class)->switchMode('block', 'admin', AuditRepository::VIA_PANEL);

        $this->api('/ok')->assertOk();
        $this->assertNull($this->ban());

        // 攻击事件保留，处置变为已解封
        $this->assertSame('unbanned', collect($this->incidents())->firstWhere('id', $incident)['disposition']);

        $audit = $this->app->make(AuditRepository::class)->paginate(null, 1, 1)['data'][0];
        $this->assertSame('mode', $audit['action']);
        $this->assertStringContainsString('1 个', $audit['detail']['text']);
        $this->assertSame(1, $audit['detail']['cleared']);
    }

    #[Test]
    public function the_console_command_clears_observation_bans_too(): void
    {
        $this->setMode('observe');

        $this->api('/_ignition/execute-solution')->assertNotFound();
        $this->api('/_ignition/execute-solution', [], self::OTHER_IP)->assertNotFound();
        $this->assertNotNull($this->ban());

        $this->artisan('fail2ban:mode', ['mode' => 'block'])->assertSuccessful();

        $this->api('/ok')->assertOk();
        $this->api('/ok', [], self::OTHER_IP)->assertOk();
        $this->assertSame([], $this->bans()->all());

        $audit = $this->app->make(AuditRepository::class)->paginate(null, 1, 1)['data'][0];
        $this->assertSame('console', $audit['via']);
        $this->assertSame(2, $audit['detail']['cleared']);
    }

    #[Test]
    public function bans_made_in_block_mode_and_manual_bans_survive_the_switch(): void
    {
        $this->setMode('block');
        $this->api('/_ignition/execute-solution')->assertNotFound();

        $this->setMode('observe');
        $this->app->make(Operations::class)->ban(self::OTHER_IP, 60, '人工', 'admin', AuditRepository::VIA_PANEL);
        $this->assertTrue($this->ban(self::OTHER_IP)['observe']);

        $this->app->make(Operations::class)->switchMode('block', 'admin', AuditRepository::VIA_PANEL);

        $this->api('/ok')->assertForbidden();
        $this->api('/ok', [], self::OTHER_IP)->assertForbidden();

        $audit = $this->app->make(AuditRepository::class)->paginate(null, 1, 1)['data'][0];
        $this->assertSame(0, $audit['detail']['cleared']);
    }

    #[Test]
    public function repeated_observation_bans_do_not_count_as_offenses(): void
    {
        $this->setMode('observe');

        foreach ([1, 2, 3] as $round) {
            $this->api("/_ignition/execute-solution?r={$round}")->assertNotFound();

            $ban = $this->ban();
            $this->assertSame(1, $ban['offense'], "observe round {$round}");
            $this->assertSame(120, $ban['ban_minutes'], "observe round {$round}");

            // 让这次封禁自然到期（不走解封，解封会清累犯记录）
            $this->expireNow('fail2ban:ban:'.self::IP, 'fail2ban:info:'.self::IP);
        }

        $this->assertNull($this->redis()->get('fail2ban:repeat:'.self::IP), '观察模式不应写累犯记录');

        $this->app->make(Operations::class)->switchMode('block', 'admin', AuditRepository::VIA_PANEL);

        $this->api('/_ignition/execute-solution')->assertNotFound();

        $ban = $this->ban();
        $this->assertFalse($ban['observe']);
        $this->assertSame(1, $ban['offense'], '拦截模式下第一次被封按第 1 次算');
        $this->assertSame(120, $ban['ban_minutes']);
    }

    #[Test]
    public function observation_bans_keep_an_existing_offense_record_untouched(): void
    {
        $this->setMode('block');
        $this->api('/_ignition/execute-solution')->assertNotFound();
        $this->assertSame(1, $this->ban()['offense']);
        $this->expireNow('fail2ban:ban:'.self::IP, 'fail2ban:info:'.self::IP);

        $this->setMode('observe');
        $this->api('/_ignition/execute-solution')->assertNotFound();
        $this->assertSame(1, $this->ban()['offense']);
        $this->assertSame(120, $this->ban()['ban_minutes']);
        $this->assertSame('1', $this->redis()->get('fail2ban:repeat:'.self::IP));
    }
}
