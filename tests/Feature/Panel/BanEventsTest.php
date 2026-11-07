<?php

namespace Maximus\Fail2Ban\Tests\Feature\Panel;

use Illuminate\Support\Facades\Event;
use Maximus\Fail2Ban\Contracts\AllowlistRepository;
use Maximus\Fail2Ban\Contracts\BanRepository;
use Maximus\Fail2Ban\Contracts\SettingsRepository;
use Maximus\Fail2Ban\Events\BanSkipped;
use Maximus\Fail2Ban\Events\IpBanned;
use Maximus\Fail2Ban\Events\IpUnbanned;
use PHPUnit\Framework\Attributes\Test;
use RuntimeException;

/**
 * 运维操作发出的事件：手动封禁发 IpBanned（source 为 manual），每解除一个封禁发一次 IpUnbanned
 * （面板或命令解封、加白名单连带解封、切到拦截时解除观察期封禁）；监听器出错不影响操作。
 * 自动封禁的 IpBanned 见 Middleware\BanFlowTest。
 */
class BanEventsTest extends PanelTestCase
{
    protected function fakeEvents(): void
    {
        Event::fake([IpBanned::class, IpUnbanned::class, BanSkipped::class]);
    }

    #[Test]
    public function a_manual_ban_from_the_panel_dispatches_ip_banned_once(): void
    {
        $this->fakeEvents();

        $id = $this->postJson($this->api('/bans'), ['ip' => '198.51.100.23', 'minutes' => 90, 'note' => '人工'])
            ->assertCreated()->json('incident_id');

        Event::assertDispatchedTimes(IpBanned::class, 1);
        Event::assertDispatched(IpBanned::class, fn (IpBanned $e) => $e->ban['source'] === 'manual'
            && $e->ban['visitor'] === '198.51.100.23'
            && $e->ban['incident'] === $id
            && $e->ban['operator'] === 'admin'
            && $e->ban['note'] === '人工'
            && $e->ban['ban_minutes'] === 90
            && $e->incident['id'] === $id
            && $e->incident['disposition'] === 'banned'
            && $e->via === 'panel');
        Event::assertNotDispatched(IpUnbanned::class);
    }

    #[Test]
    public function a_manual_ban_from_the_console_dispatches_ip_banned_with_via_console(): void
    {
        $this->fakeEvents();

        $this->artisan('fail2ban:ban', ['ip' => '198.51.100.23', '--minutes' => 30])->assertSuccessful();

        Event::assertDispatchedTimes(IpBanned::class, 1);
        Event::assertDispatched(IpBanned::class, fn (IpBanned $e) => $e->ban['source'] === 'manual'
            && $e->ban['operator'] === 'console'
            && $e->via === 'console');
    }

    #[Test]
    public function unbanning_from_the_panel_dispatches_ip_unbanned_once(): void
    {
        $ban = $this->autoBan('203.0.113.47');
        $this->fakeEvents();

        $this->deleteJson($this->api('/bans?visitor=203.0.113.47'))->assertNoContent();

        Event::assertDispatchedTimes(IpUnbanned::class, 1);
        Event::assertDispatched(IpUnbanned::class, fn (IpUnbanned $e) => $e->visitor === '203.0.113.47'
            && $e->ban['incident'] === $ban['incident']
            && $e->ban['source'] === 'auto'
            && $e->actor === 'admin'
            && $e->via === 'panel'
            && $e->reason === IpUnbanned::REASON_MANUAL);
    }

    #[Test]
    public function unbanning_from_the_console_dispatches_ip_unbanned_once(): void
    {
        $ban = $this->autoBan('2001:db8:4c2:91::/64');
        $this->fakeEvents();

        $this->artisan('fail2ban:unban', ['ip' => '2001:db8:4c2:91::77'])->assertSuccessful();

        Event::assertDispatchedTimes(IpUnbanned::class, 1);
        Event::assertDispatched(IpUnbanned::class, fn (IpUnbanned $e) => $e->visitor === '2001:db8:4c2:91::/64'
            && $e->ban['incident'] === $ban['incident']
            && $e->actor === 'console'
            && $e->via === 'console'
            && $e->reason === 'manual');
    }

    #[Test]
    public function unbanning_a_visitor_that_is_not_banned_dispatches_nothing(): void
    {
        $this->fakeEvents();

        $this->deleteJson($this->api('/bans?visitor=203.0.113.47'))->assertNotFound();
        $this->artisan('fail2ban:unban', ['ip' => '203.0.113.47'])->assertFailed();

        Event::assertNothingDispatched();
    }

    #[Test]
    public function adding_an_allowlist_entry_dispatches_ip_unbanned_for_each_lifted_ban(): void
    {
        $a = $this->autoBan('198.51.100.3');
        $b = $this->autoBan('198.51.100.14');
        $this->autoBan('198.51.100.16');                 // 不在 /28 里
        $this->fakeEvents();

        $this->postJson($this->api('/allowlist'), ['entry' => '198.51.100.0/28', 'note' => '探针'])->assertCreated();

        Event::assertDispatchedTimes(IpUnbanned::class, 2);

        foreach ([$a, $b] as $ban) {
            Event::assertDispatched(IpUnbanned::class, fn (IpUnbanned $e) => $e->visitor === $ban['visitor']
                && $e->ban['incident'] === $ban['incident']
                && $e->actor === 'admin'
                && $e->via === 'panel'
                && $e->reason === IpUnbanned::REASON_ALLOWLISTED);
        }
    }

    #[Test]
    public function switching_to_block_dispatches_ip_unbanned_for_each_cleared_observation_ban(): void
    {
        app(SettingsRepository::class)->save(['mode' => 'observe'], 'test');

        $a = $this->autoBan('203.0.113.47', details: ['observe' => true]);
        $b = $this->autoBan('203.0.113.48', details: ['observe' => true]);
        $this->autoBan('203.0.113.49');                                    // 拦截期间的自动封禁：保留
        app(BanRepository::class)->banManually('203.0.113.50', ['incident' => 'BAN-20261107-MANUAL', 'operator' => 'admin', 'observe' => true], 60);
        $this->fakeEvents();

        $this->artisan('fail2ban:mode', ['mode' => 'block'])->assertSuccessful();

        Event::assertDispatchedTimes(IpUnbanned::class, 2);

        foreach ([$a, $b] as $ban) {
            Event::assertDispatched(IpUnbanned::class, fn (IpUnbanned $e) => $e->visitor === $ban['visitor']
                && $e->ban['incident'] === $ban['incident']
                && $e->ban['observe'] === true
                && $e->actor === 'console'
                && $e->via === 'console'
                && $e->reason === IpUnbanned::REASON_OBSERVATION_CLEARED);
        }

        $this->assertEqualsCanonicalizing(['203.0.113.49', '203.0.113.50'], array_column(app(BanRepository::class)->all(), 'visitor'));
    }

    #[Test]
    public function a_throwing_listener_does_not_fail_the_operation(): void
    {
        $heard = [];

        Event::listen(IpBanned::class, function (IpBanned $e) use (&$heard) {
            $heard[] = 'banned';

            throw new RuntimeException('listener down');
        });
        Event::listen(IpUnbanned::class, function (IpUnbanned $e) use (&$heard) {
            $heard[] = $e->reason;

            throw new RuntimeException('listener down');
        });

        $bans = app(BanRepository::class);

        // 手动封禁
        $this->postJson($this->api('/bans'), ['ip' => '198.51.100.23', 'minutes' => 90, 'note' => '人工'])->assertCreated();
        $this->assertNotNull($bans->find('198.51.100.23'));

        // 面板解封
        $this->deleteJson($this->api('/bans?visitor=198.51.100.23'))->assertNoContent();
        $this->assertNull($bans->find('198.51.100.23'));
        $this->assertSame('unban', $this->lastAudit()['action']);

        // 加白名单连带解封：两个都解掉，日志写明
        $this->autoBan('198.51.100.3');
        $this->autoBan('198.51.100.14');
        $this->postJson($this->api('/allowlist'), ['entry' => '198.51.100.0/28'])->assertCreated();
        $this->assertSame([], $bans->all());
        $this->assertNotNull(app(AllowlistRepository::class)->match('198.51.100.3'));
        $this->assertEqualsCanonicalizing(['198.51.100.3', '198.51.100.14'], $this->lastAudit()['detail']['unbanned']);

        // 切到拦截：观察期封禁都解掉，日志里的个数正确
        app(SettingsRepository::class)->save(['mode' => 'observe'], 'test');
        $this->autoBan('203.0.113.47', details: ['observe' => true]);
        $this->autoBan('203.0.113.48', details: ['observe' => true]);
        $this->artisan('fail2ban:mode', ['mode' => 'block'])->assertSuccessful();
        $this->assertSame([], $bans->all());
        $this->assertSame(2, $this->lastAudit()['detail']['cleared']);

        $this->assertSame(['banned', 'manual', 'allowlisted', 'allowlisted', 'observation_cleared', 'observation_cleared'], $heard);
    }
}
