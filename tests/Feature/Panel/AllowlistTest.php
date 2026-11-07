<?php

namespace Maximus\Fail2Ban\Tests\Feature\Panel;

use Maximus\Fail2Ban\Contracts\AllowlistRepository;
use Maximus\Fail2Ban\Contracts\BanRepository;
use Maximus\Fail2Ban\Contracts\IncidentRepository;
use PHPUnit\Framework\Attributes\Test;

/**
 * 白名单接口：加进白名单后，落在其中的当前封禁立即解除。
 */
class AllowlistTest extends PanelTestCase
{
    #[Test]
    public function the_list_has_the_agreed_shape(): void
    {
        config(['fail2ban.allowlist.extra' => ['192.0.2.10']]);

        $this->postJson($this->api('/allowlist'), ['entry' => '203.0.113.10', 'note' => '办公室出口'])->assertCreated();
        $this->postJson($this->api('/allowlist'), ['entry' => '198.51.100.0/28', 'note' => ''])->assertCreated();

        $response = $this->getJson($this->api('/allowlist'))->assertOk();

        $this->assertSame(['builtin', 'data'], array_keys($response->json()));

        foreach ($response->json('builtin') as $i => $entry) {
            $this->assertShape(['entry' => 'string', 'label' => 'string'], $entry, "builtin.{$i}");
        }

        $builtin = collect($response->json('builtin'))->pluck('label', 'entry');
        $this->assertSame('内网段', $builtin['10.0.0.0/8']);
        $this->assertSame('回环', $builtin['127.0.0.0/8']);
        $this->assertSame('Cloudflare', $builtin['104.16.0.0/13']);
        $this->assertSame('配置文件', $builtin['192.0.2.10']);

        $this->assertCount(2, $response->json('data'));

        foreach ($response->json('data') as $i => $entry) {
            $this->assertShape(['entry' => 'string', 'note' => '?string', 'added_by' => 'string', 'added_at' => 'time'], $entry, "data.{$i}");
        }

        $data = collect($response->json('data'))->keyBy('entry');
        $this->assertEqualsCanonicalizing(['203.0.113.10', '198.51.100.0/28'], $data->keys()->all());
        $this->assertSame('办公室出口', $data['203.0.113.10']['note']);
        $this->assertNull($data['198.51.100.0/28']['note']);
        $this->assertSame('admin', $data['203.0.113.10']['added_by']);
    }

    #[Test]
    public function store_returns_the_entry_and_rejects_bad_input(): void
    {
        $this->postJson($this->api('/allowlist'), ['entry' => '2001:DB8:0::1', 'note' => '监控'])
            ->assertCreated()
            ->assertJsonPath('entry', '2001:db8::1')
            ->assertJsonPath('note', '监控')
            ->assertJsonPath('added_by', 'admin');

        $this->postJson($this->api('/allowlist'), ['entry' => 'not-an-ip'])->assertUnprocessable()->assertJsonValidationErrors(['entry']);
        $this->postJson($this->api('/allowlist'), ['entry' => '10.0.0.0/33'])->assertUnprocessable()->assertJsonValidationErrors(['entry']);
        $this->postJson($this->api('/allowlist'), [])->assertUnprocessable()->assertJsonValidationErrors(['entry']);
        $this->postJson($this->api('/allowlist'), ['entry' => '192.0.2.1', 'note' => str_repeat('长', 201)])
            ->assertUnprocessable()->assertJsonValidationErrors(['note']);

        $this->assertCount(1, app(AllowlistRepository::class)->entries());
    }

    #[Test]
    public function adding_an_ip_lifts_its_current_ban_i18(): void
    {
        $ban = $this->autoBan('203.0.113.47');
        $other = $this->autoBan('203.0.113.48');

        $this->postJson($this->api('/allowlist'), ['entry' => '203.0.113.47', 'note' => '误封'])->assertCreated();

        $this->assertNull(app(BanRepository::class)->lookup('203.0.113.47')['ban']);
        $this->assertSame('unbanned', app(IncidentRepository::class)->find($ban['incident'])['disposition']);

        $this->assertNotNull(app(BanRepository::class)->lookup('203.0.113.48')['ban'], '不相干的封禁不动');
        $this->assertSame('banned', app(IncidentRepository::class)->find($other['incident'])['disposition']);
    }

    #[Test]
    public function adding_a_network_lifts_every_ban_inside_it_i18(): void
    {
        $this->autoBan('198.51.100.3');
        $this->autoBan('198.51.100.14');
        $this->autoBan('198.51.100.16');                 // 不在 /28 里
        $this->autoBan('2001:db8:4c2:91::/64');
        $this->autoBan('2001:db8:4c2:92::/64');

        $this->postJson($this->api('/allowlist'), ['entry' => '198.51.100.0/28', 'note' => '探针'])->assertCreated();
        // 白名单里的单个 IPv6 地址落在被封的 /64 里：这个网段要解封，否则那个地址仍被拦。
        $this->postJson($this->api('/allowlist'), ['entry' => '2001:db8:4c2:91::abcd', 'note' => '运维'])->assertCreated();

        $remaining = array_column(app(BanRepository::class)->all(), 'visitor');
        sort($remaining);

        $this->assertSame(['198.51.100.16', '2001:db8:4c2:92::/64'], $remaining);

        // 一个网段条目覆盖 IPv6 访客键
        $this->postJson($this->api('/allowlist'), ['entry' => '2001:db8::/32'])->assertCreated();
        $this->assertSame(['198.51.100.16'], array_column(app(BanRepository::class)->all(), 'visitor'));
    }

    #[Test]
    public function removing_an_entry_uses_the_query_parameter_only(): void
    {
        $this->postJson($this->api('/allowlist'), ['entry' => '198.51.100.0/28'])->assertCreated();
        $this->postJson($this->api('/allowlist'), ['entry' => '203.0.113.10'])->assertCreated();

        $this->deleteJson($this->api('/allowlist?entry='.rawurlencode('198.51.100.0/28')))->assertNoContent();

        // 路径参数的写法已去掉（v10）：没有这条路由，条目不动
        $this->deleteJson($this->api('/allowlist/'.rawurlencode('203.0.113.10')))->assertNotFound();
        $this->assertSame(['203.0.113.10'], array_column(app(AllowlistRepository::class)->entries(), 'entry'));

        $this->deleteJson($this->api('/allowlist?entry=203.0.113.10'))->assertNoContent();
        $this->assertSame([], app(AllowlistRepository::class)->entries());

        $this->deleteJson($this->api('/allowlist?entry=203.0.113.10'))->assertNotFound();
        $this->deleteJson($this->api('/allowlist'))->assertUnprocessable()->assertJsonValidationErrors(['entry']);
    }
}
