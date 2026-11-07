<?php

namespace Maximus\Fail2Ban\Tests\Feature\Panel;

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\Redis;
use Maximus\Fail2Ban\Contracts\IncidentRepository;
use Maximus\Fail2Ban\Contracts\StatsRepository;
use Maximus\Fail2Ban\Inspector;
use PHPUnit\Framework\Attributes\Test;

class OverviewTest extends PanelTestCase
{
    #[Test]
    public function the_overview_has_the_agreed_shape(): void
    {
        $stats = app(StatsRepository::class);

        foreach (range(1, 4) as $i) {
            $this->recordHit('sensitive-path', '203.0.113.47', target: '/.env', region: '荷兰');
        }
        $this->recordHit('known-exploit', '198.51.100.23', target: '/vendor/phpunit/eval-stdin.php', region: '美国');
        $stats->incrementBlocked();
        $stats->incrementBlocked();
        $stats->incrementBans();

        $this->autoBan('203.0.113.47');
        // 累犯：封禁自然到期（封禁键没了，累犯记录还在）后再被自动封。
        $this->autoBan('198.51.100.23', 'known-exploit');
        Redis::connection('fail2ban')->del('fail2ban:ban:198.51.100.23');
        $this->autoBan('198.51.100.23', 'known-exploit');

        foreach (range(1, 6) as $i) {
            app(IncidentRepository::class)->record(['visitor' => "192.0.2.{$i}", 'disposition' => 'recorded', 'rule' => 'attack-pattern', 'count' => 5, 'observe' => true]);
        }

        $json = $this->getJson($this->api('/overview'))->assertOk()->json();

        $this->assertShape([
            'enabled' => 'bool', 'mode' => 'string', 'kpis' => 'array', 'trend' => 'list', 'rules' => 'list',
            'top_ips' => 'list', 'top_targets' => 'list', 'top_regions' => 'list', 'recent' => 'list',
        ], $json, 'overview');

        $this->assertFalse($json['enabled']);
        $this->assertSame('observe', $json['mode']);

        $this->assertShape(['blocked' => 'int', 'new_bans' => 'int', 'active_bans' => 'int', 'repeat_offenders' => 'int', 'hits' => 'int'], $json['kpis'], 'kpis');
        // hits：上面明写的 5 次，加 autoBan() 造封禁时记的命中（与中间件一样连同统计）：
        // 203.0.113.47 敏感文件 3 次 + 扫描器 1 次；198.51.100.23 两次各已知漏洞 3 次 + 扫描器 1 次。共 5 + 4 + 8 = 17。
        $this->assertSame(['blocked' => 2, 'new_bans' => 1, 'active_bans' => 2, 'repeat_offenders' => 1, 'hits' => 17], $json['kpis']);

        // 默认近 24 小时，从旧到新，每小时一项，hour 是整点
        $this->assertCount(24, $json['trend']);
        foreach ($json['trend'] as $i => $hour) {
            $this->assertShape(['hour' => 'time', 'hits' => 'int', 'blocked' => 'int', 'bans' => 'int'], $hour, "trend.{$i}");
            $this->assertStringContainsString(':00:00', $hour['hour']);
        }
        $this->assertTrue(CarbonImmutable::parse($json['trend'][0]['hour'])->lt(CarbonImmutable::parse($json['trend'][23]['hour'])));
        $this->assertSame(['hits' => 17, 'blocked' => 2, 'bans' => 1], array_intersect_key($json['trend'][23], ['hits' => 0, 'blocked' => 0, 'bans' => 0]));

        // 规则：全部列出，按命中降序
        $this->assertCount(count(app(Inspector::class)->rules()), $json['rules']);
        foreach ($json['rules'] as $i => $rule) {
            $this->assertShape(['id' => 'string', 'name' => 'string', 'hits' => 'int'], $rule, "rules.{$i}");
        }
        $this->assertSame(['id' => 'sensitive-path', 'name' => '敏感文件探测', 'hits' => 7], $json['rules'][0]);
        $this->assertSame(['id' => 'known-exploit', 'name' => '已知漏洞探测', 'hits' => 7], $json['rules'][1]);
        $this->assertSame(['id' => 'scanner-agent', 'name' => '扫描器特征', 'hits' => 3], $json['rules'][2]);

        foreach (['top_ips', 'top_targets', 'top_regions'] as $top) {
            foreach ($json[$top] as $i => $row) {
                $this->assertShape(['key' => 'string', 'count' => 'int'], $row, "{$top}.{$i}");
            }
        }
        $this->assertSame([['key' => '198.51.100.23', 'count' => 9], ['key' => '203.0.113.47', 'count' => 8]], $json['top_ips']);
        $this->assertSame(['key' => '/.env', 'count' => 4], $json['top_targets'][0]);
        $this->assertSame(['key' => '荷兰', 'count' => 4], $json['top_regions'][0]);

        $this->assertCount(5, $json['recent']);
        foreach ($json['recent'] as $i => $incident) {
            $this->assertShape($this->incidentShape(), $incident, "recent.{$i}");
        }
        $this->assertSame('192.0.2.6', $json['recent'][0]['visitor']);
        $this->assertSame(['id' => 'attack-pattern', 'name' => '攻击特征'], $json['recent'][0]['rule']);
        $this->assertTrue($json['recent'][0]['observe']);
    }

    #[Test]
    public function hours_default_to_24_and_are_capped_at_168(): void
    {
        $this->assertCount(168, $this->getJson($this->api('/overview?hours=168'))->json('trend'));
        $this->assertCount(168, $this->getJson($this->api('/overview?hours=9999'))->json('trend'));
        $this->assertCount(24, $this->getJson($this->api('/overview?hours=abc'))->json('trend'));
        $this->assertCount(1, $this->getJson($this->api('/overview?hours=0'))->json('trend'));
    }

    #[Test]
    public function the_master_switch_and_mode_are_reported(): void
    {
        config(['fail2ban.enabled' => true]);
        $this->putJson($this->api('/settings'), ['mode' => 'block'])->assertOk();

        $this->getJson($this->api('/overview'))
            ->assertJsonPath('enabled', true)
            ->assertJsonPath('mode', 'block');
    }
}
