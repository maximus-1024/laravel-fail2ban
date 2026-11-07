<?php

namespace Maximus\Fail2Ban\Tests\Feature\Panel;

use PHPUnit\Framework\Attributes\Test;

/**
 * 面板按一个 IPv6 地址搜，能搜到它所在 64 位网段的封禁与攻击事件。
 * q 能解析成 IP 时先换成访客键再匹配；其它写法（事件编号、地址片段）照旧按包含匹配。
 */
class Ipv6SearchTest extends PanelTestCase
{
    #[Test]
    public function an_ipv6_address_finds_the_ban_and_the_incident_of_its_network(): void
    {
        $ban = $this->autoBan('2001:db8:4c2:91::/64', details: ['ip' => '2001:db8:4c2:91::6']);
        $this->autoBan('2001:db8:ffff::/64', details: ['ip' => '2001:db8:ffff::1']);

        foreach (['2001:db8:4c2:91::5', '2001:DB8:4C2:91:0:0:0:abcd', '2001:db8:4c2:91::/64'] as $q) {
            $bans = $this->getJson($this->api('/bans?q='.urlencode($q)))->assertOk()->json();
            $this->assertSame(1, $bans['total'], $q);
            $this->assertSame('2001:db8:4c2:91::/64', $bans['data'][0]['visitor'], $q);

            $incidents = $this->getJson($this->api('/incidents?q='.urlencode($q)))->assertOk()->json();
            $this->assertSame(1, $incidents['total'], $q);
            $this->assertSame($ban['incident'], $incidents['data'][0]['id'], $q);
        }

        // 片段与事件编号照旧
        $this->assertSame(2, $this->getJson($this->api('/bans?q=2001:db8'))->json('total'));
        $this->assertSame(1, $this->getJson($this->api('/incidents?q='.$ban['incident']))->json('total'));
        $this->assertSame(0, $this->getJson($this->api('/bans?q=2001:db8:4c2:92::5'))->json('total'));
    }

    #[Test]
    public function an_ipv4_mapped_address_finds_the_ipv4_ban(): void
    {
        $this->autoBan('203.0.113.9');

        $this->assertSame(1, $this->getJson($this->api('/bans?q='.urlencode('::ffff:203.0.113.9')))->json('total'));
        $this->assertSame(1, $this->getJson($this->api('/incidents?q='.urlencode('::ffff:203.0.113.9')))->json('total'));
    }
}
