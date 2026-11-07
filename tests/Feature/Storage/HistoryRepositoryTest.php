<?php

namespace Maximus\Fail2Ban\Tests\Feature\Storage;

use Maximus\Fail2Ban\Contracts\AuditRepository;
use Maximus\Fail2Ban\Contracts\BanRepository;
use Maximus\Fail2Ban\Support\Text;
use Maximus\Fail2Ban\Contracts\IncidentRepository;
use Maximus\Fail2Ban\Tests\Support\InteractsWithFail2BanRedis;
use Maximus\Fail2Ban\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;

/**
 * 攻击事件与操作日志。
 */
class HistoryRepositoryTest extends TestCase
{
    use InteractsWithFail2BanRedis;

    private IncidentRepository $incidents;

    private AuditRepository $audit;

    protected function setUp(): void
    {
        parent::setUp();

        $this->incidents = $this->app->make(IncidentRepository::class);
        $this->audit = $this->app->make(AuditRepository::class);
    }

    private function incident(array $attributes = []): array
    {
        return $this->incidents->record($attributes + [
            'visitor' => '203.0.113.47',
            'ip' => '203.0.113.47',
            'rule' => 'not-found-scan',
            'disposition' => 'recorded',
        ]);
    }

    #[Test]
    public function incident_ids_have_the_agreed_format(): void
    {
        $this->travelTo(now()->setDate(2026, 11, 6));

        for ($i = 0; $i < 50; $i++) {
            $this->assertMatchesRegularExpression('/^BAN-20261106-[A-Z0-9]{6}$/', $this->incidents->nextId());
        }
    }

    #[Test]
    public function incidents_beyond_history_limit_are_dropped(): void
    {
        config(['fail2ban.history_limit' => 3]);

        foreach (range(1, 5) as $i) {
            $this->incident(['id' => "BAN-20261107-00000{$i}"]);
        }

        $page = $this->incidents->paginate();

        $this->assertSame(3, $page['total']);
        $this->assertSame(['BAN-20261107-000005', 'BAN-20261107-000004', 'BAN-20261107-000003'], array_column($page['data'], 'id'));
        $this->assertSame(3, $this->redis()->llen('fail2ban:events'));
        $this->assertNull($this->incidents->find('BAN-20261107-000001'));
    }

    #[Test]
    public function audit_entries_beyond_history_limit_are_dropped(): void
    {
        config(['fail2ban.history_limit' => 3]);

        foreach (range(1, 5) as $i) {
            $this->audit->record('admin', 'ban', "198.51.100.{$i}");
        }

        $page = $this->audit->paginate();

        $this->assertSame(3, $page['total']);
        $this->assertSame(['198.51.100.5', '198.51.100.4', '198.51.100.3'], array_column($page['data'], 'target'));
        $this->assertSame(3, $this->redis()->llen('fail2ban:audit'));
    }

    #[Test]
    public function an_incident_keeps_only_the_agreed_fields(): void
    {
        $incident = $this->incident([
            'id' => 'BAN-20261107-ABCDEF',
            'time' => 1762500000,
            'count' => 3,
            'requests' => [['time' => 1, 'method' => 'GET', 'path' => '/a', 'note' => null, 'cookie' => 'x']],
            'other_rules' => ['scanner-agent' => 2],
            'cookie' => 'session=abc',
            'body' => 'password=secret',
            'incident' => 'ignored',
            'blocked' => 9,
        ]);

        $this->assertSame([
            'id', 'time', 'visitor', 'ip', 'region', 'rule', 'source', 'count', 'disposition', 'observe',
            'operator', 'note', 'user_agent', 'first_hit_at', 'banned_at', 'unban_at', 'ban_minutes',
            'offense', 'other_rules', 'requests',
        ], array_keys($incident));
        $this->assertSame([['time' => 1, 'method' => 'GET', 'path' => '/a']], $incident['requests']);
        $this->assertSame($incident, $this->incidents->find('BAN-20261107-ABCDEF'));
        $this->assertStringNotContainsString('secret', $this->redis()->lindex('fail2ban:events', 0));
        $this->assertStringNotContainsString('session', $this->redis()->lindex('fail2ban:events', 0));
    }

    #[Test]
    public function a_ban_record_can_be_recorded_as_an_incident(): void
    {
        $bans = $this->app->make(BanRepository::class);
        $this->recordHit('sensitive-path', '203.0.113.47', '/.env', ['time' => 1762500000]);
        $ban = $bans->ban('203.0.113.47', ['incident' => $this->incidents->nextId(), 'rule' => 'sensitive-path', 'user_agent' => 'curl'], 120,
            ['enabled' => true, 'factor' => 2, 'max_days' => 7, 'keep_days' => 7]);

        $incident = $this->incidents->record(['id' => $ban['incident'], 'disposition' => 'banned', 'time' => $ban['banned_at']] + $ban);

        $this->assertSame($ban['incident'], $incident['id']);
        $this->assertSame('banned', $incident['disposition']);
        $this->assertSame('sensitive-path', $incident['rule']);
        $this->assertSame(1, $incident['count']);
        $this->assertSame(120, $incident['ban_minutes']);
        $this->assertSame(1, $incident['offense']);
        $this->assertSame($ban['unban_at'], $incident['unban_at']);
        $this->assertSame(1762500000, $incident['first_hit_at']);
        $this->assertSame('curl', $incident['user_agent']);
        $this->assertSame('/.env', $incident['requests'][0]['path']);
    }

    #[Test]
    public function the_incident_store_truncates_the_user_agent_with_the_same_limit_as_ban_records(): void
    {
        $long = str_repeat('浏览器', 100).'/tail';  // 305 个字符
        $invalid = "sqlmap\xff\xfe/1.7";

        $incident = $this->incidents->record(['disposition' => 'recorded', 'visitor' => '203.0.113.47', 'user_agent' => $long]);
        $this->assertSame(Text::USER_AGENT_MAX, mb_strlen($incident['user_agent']));
        $this->assertSame(mb_substr($long, 0, Text::USER_AGENT_MAX), $incident['user_agent']);
        $this->assertSame($incident['user_agent'], $this->incidents->find($incident['id'])['user_agent']);

        $this->assertTrue(mb_check_encoding($this->incidents->record(['disposition' => 'recorded', 'visitor' => 'v', 'user_agent' => $invalid])['user_agent'], 'UTF-8'));
        $this->assertNull($this->incidents->record(['disposition' => 'recorded', 'visitor' => 'v', 'user_agent' => ''])['user_agent']);

        // 封禁记录用同一个上限
        $ban = $this->app->make(BanRepository::class)->ban('203.0.113.48', ['incident' => $this->incidents->nextId(), 'rule' => 'scanner-agent', 'user_agent' => $long], 10,
            ['enabled' => true, 'factor' => 2, 'max_days' => 7, 'keep_days' => 7]);
        $this->assertSame($incident['user_agent'], $ban['user_agent']);
    }

    #[Test]
    public function expired_is_derived_from_the_unban_time(): void
    {
        $this->incident(['id' => 'BAN-20261107-PAST01', 'disposition' => 'banned', 'unban_at' => time() - 1]);
        $this->incident(['id' => 'BAN-20261107-FUTURE', 'disposition' => 'banned', 'unban_at' => time() + 600]);

        $this->assertSame('expired', $this->incidents->find('BAN-20261107-PAST01')['disposition']);
        $this->assertSame('banned', $this->incidents->find('BAN-20261107-FUTURE')['disposition']);
        $this->assertSame(['BAN-20261107-PAST01'], array_column($this->incidents->paginate(['disposition' => 'expired'])['data'], 'id'));
    }

    #[Test]
    public function mark_unbanned_rewrites_only_that_incident(): void
    {
        $this->incident(['id' => 'BAN-20261107-TARGET', 'disposition' => 'banned', 'unban_at' => time() + 600, 'note' => '"disposition":"banned"']);
        $this->incident(['id' => 'BAN-20261107-OTHER1', 'disposition' => 'banned', 'unban_at' => time() + 600]);
        $this->incident(['id' => 'BAN-20261107-EXEMPT', 'disposition' => 'exempted']);

        $this->assertTrue($this->incidents->markUnbanned('BAN-20261107-TARGET'));
        $this->assertFalse($this->incidents->markUnbanned('BAN-20261107-TARGET'));
        $this->assertFalse($this->incidents->markUnbanned('BAN-20261107-EXEMPT'));
        $this->assertFalse($this->incidents->markUnbanned('BAN-20261107-NOPE00'));

        $target = $this->incidents->find('BAN-20261107-TARGET');
        $this->assertSame('unbanned', $target['disposition']);
        $this->assertSame('"disposition":"banned"', $target['note']);
        $this->assertSame('banned', $this->incidents->find('BAN-20261107-OTHER1')['disposition']);
        $this->assertSame(3, $this->redis()->llen('fail2ban:events'));
    }

    #[Test]
    public function incidents_can_be_filtered_and_paginated(): void
    {
        $this->incident(['id' => 'BAN-20261107-AAAAA1', 'rule' => 'not-found-scan', 'disposition' => 'recorded']);
        $this->incident(['id' => 'BAN-20261107-AAAAA2', 'rule' => 'scanner-agent', 'disposition' => 'exempted', 'visitor' => '198.51.100.9', 'ip' => '198.51.100.9']);
        $this->incident(['id' => 'BAN-20261107-AAAAA3', 'rule' => null, 'source' => 'manual', 'disposition' => 'banned', 'unban_at' => time() + 60, 'operator' => 'admin']);
        $this->incident(['id' => 'BAN-20261107-BBBBB4', 'rule' => 'not-found-scan', 'disposition' => 'banned', 'unban_at' => time() + 60, 'visitor' => '2001:db8::/64', 'ip' => '2001:db8::1']);

        $ids = fn (array $filters, int $page = 1, int $perPage = 20) => array_column($this->incidents->paginate($filters, $page, $perPage)['data'], 'id');

        $this->assertSame(['BAN-20261107-BBBBB4', 'BAN-20261107-AAAAA1'], $ids(['rule' => 'not-found-scan']));
        $this->assertSame(['BAN-20261107-AAAAA3'], $ids(['rule' => 'manual']));
        $this->assertSame(['BAN-20261107-AAAAA2'], $ids(['disposition' => 'exempted']));
        $this->assertSame(['BAN-20261107-BBBBB4', 'BAN-20261107-AAAAA3'], $ids(['disposition' => 'banned']));
        $this->assertSame(['BAN-20261107-AAAAA2'], $ids(['q' => '198.51.100']));
        $this->assertSame(['BAN-20261107-BBBBB4'], $ids(['q' => 'ban-20261107-bbb']));
        $this->assertSame(['BAN-20261107-BBBBB4'], $ids(['q' => '2001:db8::1']));
        $this->assertSame(['BAN-20261107-AAAAA2', 'BAN-20261107-AAAAA1'], $ids([], 2, 2));

        $page = $this->incidents->paginate([], 2, 3);
        $this->assertSame([4, 2, 3], [$page['total'], $page['page'], $page['per_page']]);
        $this->assertSame(['BAN-20261107-AAAAA1'], array_column($page['data'], 'id'));
    }

    #[Test]
    public function audit_entries_can_be_filtered_by_action(): void
    {
        $this->audit->record('admin', 'ban', '203.0.113.1', '手动封禁 60 分钟');
        $this->audit->record('bob', 'settings', null, ['mode' => ['observe', 'block']]);
        $entry = $this->audit->record('admin', 'unban', '203.0.113.1');

        $this->assertSame(['time', 'operator', 'action', 'target', 'detail', 'via'], array_keys($entry));
        $this->assertNull($entry['via']);
        $this->assertSame(['unban', 'settings', 'ban'], array_column($this->audit->paginate()['data'], 'action'));

        $this->audit->record('ops', 'mode', '运行模式', ['text' => '由「观察」改为「拦截」'], 'console');
        $this->assertSame([['text' => '由「观察」改为「拦截」'], 'console'], [$this->audit->paginate('mode')['data'][0]['detail'], $this->audit->paginate('mode')['data'][0]['via']]);

        $settings = $this->audit->paginate('settings');
        $this->assertSame(1, $settings['total']);
        $this->assertSame(['mode' => ['observe', 'block']], $settings['data'][0]['detail']);
        $this->assertSame('bob', $settings['data'][0]['operator']);
    }
}
