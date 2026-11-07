<?php

namespace Maximus\Fail2Ban\Tests\Feature\Console;

use Maximus\Fail2Ban\Contracts\AllowlistRepository;
use Maximus\Fail2Ban\Contracts\AuditRepository;
use Maximus\Fail2Ban\Contracts\BanRepository;
use Maximus\Fail2Ban\Contracts\IncidentRepository;
use Maximus\Fail2Ban\Contracts\SettingsRepository;
use Maximus\Fail2Ban\Fail2Ban;
use Maximus\Fail2Ban\Tests\Feature\Panel\PanelTestCase;
use PHPUnit\Framework\Attributes\Test;

/**
 * fail2ban:unban、fail2ban:ban、fail2ban:mode：成功与失败的命令行一侧。
 */
class CommandsTest extends PanelTestCase
{
    protected function lastAuditEntry(): array
    {
        return app(AuditRepository::class)->paginate(null, 1, 1)['data'][0];
    }

    #[Test]
    public function unban_lifts_the_ban_immediately_and_marks_the_incident_i11(): void
    {
        $ban = $this->autoBan('203.0.113.47');

        $this->artisan('fail2ban:unban', ['ip' => '203.0.113.47'])
            ->expectsOutputToContain('已解封 203.0.113.47')
            ->assertSuccessful();

        $this->assertNull(app(BanRepository::class)->lookup('203.0.113.47')['ban']);
        $this->assertSame('unbanned', app(IncidentRepository::class)->find($ban['incident'])['disposition']);

        $entry = $this->lastAuditEntry();
        $this->assertSame(['unban', 'console', '203.0.113.47', 'console'], [$entry['action'], $entry['operator'], $entry['target'], $entry['via']]);
    }

    #[Test]
    public function unban_accepts_any_address_in_an_ipv6_network(): void
    {
        $this->autoBan('2001:db8:4c2:91::/64');

        $this->artisan('fail2ban:unban', ['ip' => '2001:db8:4c2:91::1234'])->assertSuccessful();

        $this->assertNull(app(BanRepository::class)->lookup('2001:db8:4c2:91::/64')['ban']);
    }

    #[Test]
    public function unban_fails_for_an_invalid_ip_or_a_visitor_that_is_not_banned(): void
    {
        $this->artisan('fail2ban:unban', ['ip' => 'not-an-ip'])
            ->expectsOutputToContain('不是合法的 IP')
            ->assertFailed();
        $this->assertSame(0, $this->auditCount());

        $this->artisan('fail2ban:unban', ['ip' => '203.0.113.47'])
            ->expectsOutputToContain('当前没有封禁')
            ->assertFailed();
        $this->assertSame('unban', $this->lastAuditEntry()['action'], '清掉了命中与累犯记录，也留一条日志');
    }

    #[Test]
    public function ban_writes_a_manual_ban_with_duration_note_and_operator_i19(): void
    {
        $this->artisan('fail2ban:ban', ['ip' => '198.51.100.23', '--minutes' => 45, '--note' => '命令行封禁'])
            ->expectsOutputToContain('已封禁 198.51.100.23 45 分钟')
            ->assertSuccessful();

        $ban = app(BanRepository::class)->find('198.51.100.23');
        $this->assertSame(['manual', 45, '命令行封禁', 'console'], [$ban['source'], $ban['ban_minutes'], $ban['note'], $ban['operator']]);
        $this->assertSame('banned', app(IncidentRepository::class)->find($ban['incident'])['disposition']);

        $entry = $this->lastAuditEntry();
        $this->assertSame(['ban', 'console', 'console'], [$entry['action'], $entry['operator'], $entry['via']]);

        // 面板列表里如实显示
        $listed = $this->getJson('/fail2ban/api/bans')->json('data.0');
        $this->assertSame([2700, '命令行封禁', 'console', '由 console 操作：命令行封禁'], [$listed['total_seconds'], $listed['note'], $listed['operator'], $listed['reason']]);

        // 再封一次以最后一次为准；不填备注、默认 60 分钟
        $this->artisan('fail2ban:ban', ['ip' => '198.51.100.23'])->assertSuccessful();
        $ban = app(BanRepository::class)->find('198.51.100.23');
        $this->assertSame([60, null], [$ban['ban_minutes'], $ban['note']]);
        $this->assertCount(1, app(BanRepository::class)->all());
    }

    #[Test]
    public function ban_rejects_invalid_allowlisted_exempt_ips_and_bad_minutes(): void
    {
        app(AllowlistRepository::class)->add('203.0.113.10', null, 'admin');
        Fail2Ban::exemptUsing(fn (string $ip, $request) => $request === null && $ip === '192.0.2.200');

        $this->artisan('fail2ban:ban', ['ip' => 'not-an-ip'])->expectsOutputToContain('不是合法的 IP')->assertFailed();
        $this->artisan('fail2ban:ban', ['ip' => '203.0.113.10'])->expectsOutputToContain('白名单')->assertFailed();
        $this->artisan('fail2ban:ban', ['ip' => '10.0.0.8'])->expectsOutputToContain('白名单')->assertFailed();
        $this->artisan('fail2ban:ban', ['ip' => '192.0.2.200'])->expectsOutputToContain('豁免')->assertFailed();
        $this->artisan('fail2ban:ban', ['ip' => '192.0.2.9', '--minutes' => '0'])->expectsOutputToContain('封禁时长')->assertFailed();
        $this->artisan('fail2ban:ban', ['ip' => '192.0.2.9', '--minutes' => 'abc'])->expectsOutputToContain('封禁时长')->assertFailed();

        $this->assertSame([], app(BanRepository::class)->all());
        $this->assertSame(0, $this->auditCount());
    }

    #[Test]
    public function mode_switches_the_running_mode(): void
    {
        $this->artisan('fail2ban:mode', ['mode' => 'block'])
            ->expectsOutputToContain('拦截')
            ->expectsOutputToContain('总开关')
            ->assertSuccessful();

        $this->assertSame('block', app(SettingsRepository::class)->all()['mode']);
        $this->assertSame('console', app(SettingsRepository::class)->all()['updated_by']);

        $entry = $this->lastAuditEntry();
        $this->assertSame(['mode', 'console', 'console', 'observe', 'block'], [
            $entry['action'], $entry['operator'], $entry['via'], $entry['detail']['old'], $entry['detail']['new'],
        ]);

        // 再切到同一个模式也留一条
        $this->artisan('fail2ban:mode', ['mode' => 'block'])->assertSuccessful();
        $this->assertSame(2, $this->auditCount());
    }

    #[Test]
    public function mode_rejects_an_unknown_mode(): void
    {
        $this->artisan('fail2ban:mode', ['mode' => 'panic'])
            ->expectsOutputToContain('off、observe、block')
            ->assertFailed();

        $this->assertSame('observe', app(SettingsRepository::class)->all()['mode']);
        $this->assertSame(0, $this->auditCount());
    }

    #[Test]
    public function each_command_leaves_exactly_one_audit_entry_i17(): void
    {
        $this->autoBan('203.0.113.47');

        foreach ([
            'unban' => ['fail2ban:unban', ['ip' => '203.0.113.47']],
            'ban' => ['fail2ban:ban', ['ip' => '203.0.113.47', '--minutes' => 5]],
            'mode' => ['fail2ban:mode', ['mode' => 'off']],
        ] as $action => [$command, $arguments]) {
            $before = $this->auditCount();

            $this->artisan($command, $arguments)->assertSuccessful();

            $this->assertSame($before + 1, $this->auditCount(), $command);
            $entry = $this->lastAuditEntry();
            $this->assertSame([$action, 'console', 'console'], [$entry['action'], $entry['operator'], $entry['via']]);
        }
    }
}
