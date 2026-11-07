<?php

namespace Maximus\Fail2Ban\Tests\Feature\Panel;

use Maximus\Fail2Ban\Contracts\BanRepository;
use Maximus\Fail2Ban\Contracts\IncidentRepository;
use PHPUnit\Framework\Attributes\Test;

class IncidentsTest extends PanelTestCase
{
    #[Test]
    public function the_list_has_the_agreed_shape_pagination_and_filters(): void
    {
        $banned = $this->autoBan('203.0.113.47');
        $this->autoBan('2001:db8:4c2:91::/64', 'not-found-scan');
        $incidents = app(IncidentRepository::class);
        $incidents->record(['visitor' => '192.0.2.60', 'disposition' => 'exempted', 'rule' => 'not-found-scan', 'count' => 10]);
        $incidents->record(['visitor' => '192.0.2.33', 'disposition' => 'recorded', 'rule' => 'attack-pattern', 'count' => 5, 'observe' => true]);
        $this->postJson($this->api('/bans'), ['ip' => '192.0.2.118', 'minutes' => 60, 'note' => '手动'])->assertCreated();

        $json = $this->getJson($this->api('/incidents'))->assertOk()->json();

        $this->assertSame(['data', 'total', 'page', 'per_page', 'history_limit'], array_keys($json));
        $this->assertSame([5, 1, 20, 500], [$json['total'], $json['page'], $json['per_page'], $json['history_limit']]);

        foreach ($json['data'] as $i => $incident) {
            $this->assertShape($this->incidentShape(), $incident, "data.{$i}");
        }

        $this->assertSame('192.0.2.118', $json['data'][0]['visitor']);
        $this->assertSame('manual', $json['data'][0]['source']);
        $this->assertNull($json['data'][0]['rule']);
        $this->assertSame('admin', $json['data'][0]['operator']);
        $this->assertSame('手动', $json['data'][0]['note']);

        // 分页
        $page = $this->getJson($this->api('/incidents?page=2&per_page=2'))->json();
        $this->assertSame([5, 2, 2], [$page['total'], $page['page'], $page['per_page']]);
        $this->assertSame([$json['data'][2]['id'], $json['data'][3]['id']], array_column($page['data'], 'id'));

        // 筛选
        $this->assertSame(['192.0.2.60'], $this->getJson($this->api('/incidents?disposition=exempted'))->json('data.*.visitor'));
        $this->assertSame(['192.0.2.118'], $this->getJson($this->api('/incidents?rule=manual'))->json('data.*.visitor'));
        $this->assertEqualsCanonicalizing(['2001:db8:4c2:91::/64', '192.0.2.60'], $this->getJson($this->api('/incidents?rule=not-found-scan'))->json('data.*.visitor'));
        $this->assertSame([$banned['incident']], $this->getJson($this->api('/incidents?q='.strtolower($banned['incident'])))->json('data.*.id'));
        $this->assertSame(['203.0.113.47'], $this->getJson($this->api('/incidents?q=203.0.113.47'))->json('data.*.visitor'));
        $this->assertSame(['2001:db8:4c2:91::/64'], $this->getJson($this->api('/incidents?disposition=banned&rule=not-found-scan&q=2001'))->json('data.*.visitor'));
    }

    #[Test]
    public function the_detail_merges_live_ban_fields_while_the_ban_is_active(): void
    {
        $ban = $this->autoBan('203.0.113.47');
        app(BanRepository::class)->recordBlock('203.0.113.47');
        app(BanRepository::class)->recordBlock('203.0.113.47');
        app(BanRepository::class)->recordBlock('203.0.113.47');

        $json = $this->getJson($this->api('/incidents/'.$ban['incident']))->assertOk()->json();

        $this->assertShape($this->incidentShape() + [
            'reason' => '?string', 'user_agent' => '?string', 'first_hit_at' => '?time', 'banned_at' => '?time',
            'unban_at' => '?time', 'remaining_seconds' => '?int', 'ban_minutes' => '?int', 'offense' => '?int',
            'blocked' => '?int', 'last_blocked_at' => '?time', 'other_rules' => 'list', 'requests' => 'list',
        ], $json, 'incident');

        $this->assertSame('banned', $json['disposition']);
        $this->assertSame('10 分钟内 3 个不同地址', $json['reason']);
        $this->assertSame('Mozilla/5.0 zgrab/0.x', $json['user_agent']);
        $this->assertSame(3, $json['blocked']);
        $this->assertNotNull($json['last_blocked_at']);
        $this->assertEqualsWithDelta(7200, $json['remaining_seconds'], 2);
        $this->assertSame(120, $json['ban_minutes']);
        $this->assertSame(1, $json['offense']);
        $this->assertSame(3, $json['count']);
        $this->assertSame([['id' => 'scanner-agent', 'name' => '扫描器特征', 'count' => 1]], $json['other_rules']);

        $this->assertCount(3, $json['requests']);
        foreach ($json['requests'] as $i => $request) {
            $this->assertShape(['time' => 'time', 'method' => '?string', 'path' => '?string'], $request, "requests.{$i}");
        }
        $this->assertEqualsCanonicalizing(['/.env', '/.git/config', '/backup.zip'], array_column($json['requests'], 'path'));

        // 解封后：实时字段为 null，处置为已解封
        $this->deleteJson($this->api('/bans?visitor=203.0.113.47'))->assertNoContent();

        $after = $this->getJson($this->api('/incidents/'.$ban['incident']))->json();
        $this->assertSame('unbanned', $after['disposition']);
        $this->assertNull($after['remaining_seconds']);
        $this->assertNull($after['blocked']);
        $this->assertNull($after['last_blocked_at']);
        $this->assertSame($json['banned_at'], $after['banned_at']);
    }

    #[Test]
    public function manual_and_exempted_details_have_readable_reasons(): void
    {
        $id = $this->postJson($this->api('/bans'), ['ip' => '192.0.2.118', 'minutes' => 60, 'note' => '反复用错误签名'])->json('incident_id');

        $this->getJson($this->api('/incidents/'.$id))
            ->assertOk()
            ->assertJsonPath('reason', '由 admin 操作：反复用错误签名')
            ->assertJsonPath('blocked', 0)
            ->assertJsonPath('ban_minutes', 60)
            ->assertJsonPath('requests', [])
            ->assertJsonPath('other_rules', []);

        $exempted = app(IncidentRepository::class)->record(['visitor' => '192.0.2.60', 'disposition' => 'exempted', 'rule' => 'scanner-agent', 'count' => 2]);
        $this->getJson($this->api('/incidents/'.$exempted['id']))->assertJsonPath('reason', '10 分钟内 2 次')->assertJsonPath('blocked', null);

        $once = app(IncidentRepository::class)->record(['visitor' => '192.0.2.61', 'disposition' => 'recorded', 'rule' => 'known-exploit', 'count' => 1]);
        $this->getJson($this->api('/incidents/'.$once['id']))->assertJsonPath('reason', '命中 1 次即封');

        $attack = app(IncidentRepository::class)->record(['visitor' => '192.0.2.62', 'disposition' => 'recorded', 'rule' => 'attack-pattern', 'count' => 5]);
        $this->getJson($this->api('/incidents/'.$attack['id']))->assertJsonPath('reason', '1 分钟内 5 个不同地址');
    }

    #[Test]
    public function unknown_incidents_are_404(): void
    {
        $this->getJson($this->api('/incidents/BAN-20261107-NOPE00'))->assertNotFound()->assertJsonStructure(['message']);
    }
}
