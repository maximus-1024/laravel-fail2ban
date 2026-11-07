<?php

namespace Maximus\Fail2Ban\Tests\Feature\Panel;

use Maximus\Fail2Ban\Contracts\AllowlistRepository;
use Maximus\Fail2Ban\Contracts\BanRepository;
use Maximus\Fail2Ban\Contracts\IncidentRepository;
use Maximus\Fail2Ban\Fail2Ban;
use PHPUnit\Framework\Attributes\Test;

/**
 * 封禁列表、手动封禁、解封。
 */
class BansTest extends PanelTestCase
{
    #[Test]
    public function the_list_has_the_agreed_shape_and_filters(): void
    {
        $auto = $this->autoBan('203.0.113.47');
        $v6 = $this->autoBan('2001:db8:4c2:91::/64', 'not-found-scan', ['ip' => '2001:db8:4c2:91::5'], 30);
        app(BanRepository::class)->recordBlock('203.0.113.47');
        app(BanRepository::class)->recordBlock('203.0.113.47');

        $this->postJson($this->api('/bans'), ['ip' => '192.0.2.118', 'minutes' => 1440, 'note' => '反复用错误签名请求代付接口'])->assertCreated();

        $response = $this->getJson($this->api('/bans'))->assertOk();

        $this->assertSame(['data', 'total'], array_keys($response->json()));
        $this->assertSame(3, $response->json('total'));

        foreach ($response->json('data') as $i => $ban) {
            $this->assertShape($this->banShape(), $ban, "data.{$i}");
        }

        // 按解封时间升序：30 分钟、120 分钟、1440 分钟。
        $this->assertSame(['2001:db8:4c2:91::/64', '203.0.113.47', '192.0.2.118'], $response->json('data.*.visitor'));

        [$first, $second, $manual] = $response->json('data');

        $this->assertSame('IPv6 按 64 位网段封禁', $first['visitor_note']);
        $this->assertSame(['id' => 'not-found-scan', 'name' => '404 扫描'], $first['rule']);
        $this->assertSame('5 分钟内 3 个不同地址', $first['reason']);
        $this->assertSame($v6['incident'], $first['incident_id']);

        $this->assertNull($second['visitor_note']);
        $this->assertSame('荷兰', $second['region']);
        $this->assertSame(['id' => 'sensitive-path', 'name' => '敏感文件探测'], $second['rule']);
        $this->assertSame('10 分钟内 3 个不同地址', $second['reason']);
        $this->assertSame('auto', $second['source']);
        $this->assertSame(2, $second['blocked']);
        $this->assertSame(1, $second['offense']);
        $this->assertSame(7200, $second['total_seconds']);
        $this->assertEqualsWithDelta(7200, $second['remaining_seconds'], 2);
        $this->assertSame($auto['incident'], $second['incident_id']);

        $this->assertSame('manual', $manual['source']);
        $this->assertNull($manual['rule']);
        $this->assertSame('由 admin 操作：反复用错误签名请求代付接口', $manual['reason']);

        // 筛选：规则、manual、q（访客键或 IP 或事件编号的一部分）
        $this->assertSame(['203.0.113.47'], $this->getJson($this->api('/bans?rule=sensitive-path'))->json('data.*.visitor'));
        $this->assertSame(['192.0.2.118'], $this->getJson($this->api('/bans?rule=manual'))->json('data.*.visitor'));
        $this->assertSame(['2001:db8:4c2:91::/64'], $this->getJson($this->api('/bans?q=2001:DB8'))->json('data.*.visitor'));
        $this->assertSame(['203.0.113.47'], $this->getJson($this->api('/bans?q='.$auto['incident']))->json('data.*.visitor'));
        $this->assertSame(0, $this->getJson($this->api('/bans?rule=scanner-agent'))->json('total'));
    }

    #[Test]
    public function a_manual_ban_records_duration_note_and_operator_i19(): void
    {
        $response = $this->postJson($this->api('/bans'), ['ip' => '198.51.100.23', 'minutes' => 90, 'note' => '<b>人工</b> "封"'])
            ->assertCreated();

        $this->assertShape($this->banShape(), $response->json(), 'POST /bans');
        $this->assertSame('manual', $response->json('source'));
        $this->assertSame('admin', $response->json('operator'));
        $this->assertSame('<b>人工</b> "封"', $response->json('note'));
        $this->assertSame(5400, $response->json('total_seconds'));

        $listed = $this->getJson($this->api('/bans'))->json('data.0');
        $this->assertSame('198.51.100.23', $listed['visitor']);
        $this->assertSame('admin', $listed['operator']);
        $this->assertSame('<b>人工</b> "封"', $listed['note']);
        $this->assertSame(5400, $listed['total_seconds']);
        $this->assertEqualsWithDelta(5400, $listed['remaining_seconds'], 2);

        // 存储层：封禁键在、来源手动；有一条处置为已封禁的手动事件。
        $this->assertSame($listed['incident_id'], app(BanRepository::class)->lookup('198.51.100.23')['ban']['incident']);

        $incident = app(IncidentRepository::class)->find($listed['incident_id']);
        $this->assertSame('banned', $incident['disposition']);
        $this->assertSame('manual', $incident['source']);
        $this->assertSame('admin', $incident['operator']);
    }

    #[Test]
    public function banning_the_same_visitor_again_keeps_the_last_ban_i19(): void
    {
        $auto = $this->autoBan('203.0.113.47');

        $first = $this->postJson($this->api('/bans'), ['ip' => '203.0.113.47', 'minutes' => 600, 'note' => '第一次'])->assertCreated()->json();
        Fail2Ban::actorUsing(fn () => 'other-admin');
        $second = $this->postJson($this->api('/bans'), ['ip' => '203.0.113.47', 'minutes' => 15, 'note' => '第二次'])->assertCreated()->json();

        $list = $this->getJson($this->api('/bans'))->json();

        $this->assertSame(1, $list['total']);
        $this->assertSame($second['incident_id'], $list['data'][0]['incident_id']);
        $this->assertSame(900, $list['data'][0]['total_seconds']);
        $this->assertSame('第二次', $list['data'][0]['note']);
        $this->assertSame('other-admin', $list['data'][0]['operator']);

        // 被覆盖的两次封禁的事件不再显示为已封禁。
        $this->assertSame('unbanned', app(IncidentRepository::class)->find($auto['incident'])['disposition']);
        $this->assertSame('unbanned', app(IncidentRepository::class)->find($first['incident_id'])['disposition']);
        $this->assertSame('banned', app(IncidentRepository::class)->find($second['incident_id'])['disposition']);
    }

    #[Test]
    public function an_ipv6_address_is_banned_by_its_64_bit_network(): void
    {
        $this->postJson($this->api('/bans'), ['ip' => '2001:db8:4c2:91:aaaa::1', 'minutes' => 10, 'note' => 'v6'])
            ->assertCreated()
            ->assertJsonPath('visitor', '2001:db8:4c2:91::/64')
            ->assertJsonPath('visitor_note', 'IPv6 按 64 位网段封禁');

        $this->assertNotNull(app(BanRepository::class)->lookup('2001:db8:4c2:91::/64')['ban']);
    }

    #[Test]
    public function invalid_allowlisted_and_exempt_ips_are_rejected_i19(): void
    {
        app(AllowlistRepository::class)->add('198.51.100.0/28', '探针', 'admin');
        Fail2Ban::exemptUsing(fn (string $ip) => $ip === '203.0.113.200');

        $cases = [
            ['not-an-ip', 'ip'],
            ['203.0.113.300', 'ip'],
            ['2001:db8::/64', 'ip'],
            ['198.51.100.5', 'ip'],     // 面板白名单
            ['10.1.2.3', 'ip'],         // 内置：内网段
            ['104.16.0.1', 'ip'],       // 内置：Cloudflare
            ['127.0.0.1', 'ip'],        // 内置：回环
            ['203.0.113.200', 'ip'],    // 宿主豁免
        ];

        foreach ($cases as [$ip, $field]) {
            $this->postJson($this->api('/bans'), ['ip' => $ip, 'minutes' => 10, 'note' => 'x'])
                ->assertUnprocessable()
                ->assertJsonValidationErrors([$field])
                ->assertJsonStructure(['message', 'errors']);
        }

        $this->postJson($this->api('/bans'), ['ip' => '203.0.113.9', 'minutes' => 0, 'note' => 'x'])
            ->assertUnprocessable()->assertJsonValidationErrors(['minutes']);
        $this->postJson($this->api('/bans'), ['ip' => '203.0.113.9', 'minutes' => 43201, 'note' => 'x'])
            ->assertUnprocessable()->assertJsonValidationErrors(['minutes']);
        $this->postJson($this->api('/bans'), ['ip' => '203.0.113.9', 'minutes' => 'abc', 'note' => 'x'])
            ->assertUnprocessable()->assertJsonValidationErrors(['minutes']);
        $this->postJson($this->api('/bans'), ['ip' => '203.0.113.9', 'minutes' => 10, 'note' => '  '])
            ->assertUnprocessable()->assertJsonValidationErrors(['note']);
        $this->postJson($this->api('/bans'), [])
            ->assertUnprocessable()->assertJsonValidationErrors(['ip', 'minutes', 'note']);

        $this->assertSame([], app(BanRepository::class)->all());
        $this->assertSame(0, app(IncidentRepository::class)->paginate()['total']);
        $this->assertSame(0, $this->auditCount());
    }

    #[Test]
    public function unbanning_from_the_panel_lifts_the_ban_immediately_i11(): void
    {
        $ban = $this->autoBan('203.0.113.47');

        $this->deleteJson($this->api('/bans?visitor=203.0.113.47'))->assertNoContent();

        $this->assertNull(app(BanRepository::class)->lookup('203.0.113.47')['ban']);
        $this->assertSame('unbanned', app(IncidentRepository::class)->find($ban['incident'])['disposition']);
        $this->assertSame(0, $this->getJson($this->api('/bans'))->json('total'));

        // 再解封一次：已经没有封禁了。
        $this->deleteJson($this->api('/bans?visitor=203.0.113.47'))->assertNotFound()->assertJsonStructure(['message']);
    }

    #[Test]
    public function an_ipv6_network_is_unbanned_through_the_query_parameter_only(): void
    {
        $this->autoBan('2001:db8:4c2:91::/64');
        $this->deleteJson($this->api('/bans?visitor='.rawurlencode('2001:db8:4c2:91::/64')))->assertNoContent();
        $this->assertNull(app(BanRepository::class)->lookup('2001:db8:4c2:91::/64')['ban']);

        // 路径参数的写法已去掉（v10）：没有这条路由，封禁不动
        $this->autoBan('2001:db8:4c2:91::/64');
        $this->deleteJson($this->api('/bans/'.rawurlencode('2001:db8:4c2:91::/64')))->assertNotFound();
        $this->deleteJson($this->api('/bans/203.0.113.9'))->assertNotFound();
        $this->assertNotNull(app(BanRepository::class)->lookup('2001:db8:4c2:91::/64')['ban']);
        $this->deleteJson($this->api('/bans?visitor='.rawurlencode('2001:db8:4c2:91::/64')))->assertNoContent();

        // 给出网段里的任意地址也解封同一个访客键。
        $this->autoBan('2001:db8:4c2:91::/64');
        $this->deleteJson($this->api('/bans?visitor=2001:db8:4c2:91::77'))->assertNoContent();
        $this->assertNull(app(BanRepository::class)->lookup('2001:db8:4c2:91::/64')['ban']);
    }

    #[Test]
    public function unbanning_requires_a_valid_visitor(): void
    {
        $this->deleteJson($this->api('/bans'))->assertUnprocessable()->assertJsonValidationErrors(['visitor']);
        $this->deleteJson($this->api('/bans?visitor=nope'))->assertUnprocessable()->assertJsonValidationErrors(['visitor']);
        $this->assertSame(0, $this->auditCount());
    }
}
