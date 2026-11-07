<?php

namespace Maximus\Fail2Ban\Tests\Feature\Middleware;

use Illuminate\Http\Middleware\TrustProxies;
use PHPUnit\Framework\Attributes\Test;

/**
 * 被计入、被封的是访客而不是代理，IPv6 按 64 位网段。
 */
class VisitorIdentityTest extends MiddlewareTestCase
{
    private const PROXY = '10.0.0.5';

    #[Test]
    public function behind_a_trusted_proxy_the_rightmost_forwarded_address_is_banned(): void
    {
        TrustProxies::at(self::PROXY);
        $this->setMode('block');

        // 访客自带的假地址在最左；受信代理追加的真实对端地址在最右
        $forwarded = ['X-Forwarded-For' => '192.0.2.200, '.self::IP];

        $this->api('/_ignition/execute-solution', $forwarded, self::PROXY)->assertNotFound();

        $this->assertNotNull($ban = $this->ban(self::IP));
        $this->assertSame(self::IP, $ban['ip']);
        $this->assertNull($this->ban('192.0.2.200'));
        $this->assertNull($this->ban(self::PROXY));

        $this->api('/ok', $forwarded, self::PROXY)->assertForbidden();
        $this->api('/ok', ['X-Forwarded-For' => self::IP], self::PROXY)->assertForbidden();

        // 经同一个代理来的另一个访客不受影响
        $this->api('/ok', ['X-Forwarded-For' => self::OTHER_IP], self::PROXY)->assertOk();
        $this->assertSame(1, static::$controllerRuns);
    }

    #[Test]
    public function without_trusting_the_proxy_the_forwarded_header_is_ignored(): void
    {
        $this->setMode('block');

        // 对端不是受信代理：自报的 X-Forwarded-For 不算数，被封的是对端
        $this->api('/_ignition/execute-solution', ['X-Forwarded-For' => self::OTHER_IP], self::IP)->assertNotFound();

        $this->assertNotNull($this->ban(self::IP));
        $this->assertNull($this->ban(self::OTHER_IP));
    }

    #[Test]
    public function ipv6_addresses_in_the_same_64_network_are_one_visitor(): void
    {
        $this->setMode('block');
        $this->setRule('sensitive-path', ['count' => 3]);

        $this->api('/.env', [], '2001:db8:4c2:91::1')->assertNotFound();
        $this->api('/.git/config', [], '2001:db8:4c2:91:aaaa:bbbb:cccc:dddd')->assertNotFound();
        $this->assertSame(['sensitive-path' => 2], $this->hitCounts('2001:db8:4c2:91::ffff'));
        $this->assertNull($this->ban('2001:db8:4c2:91::1'));

        $this->api('/.htpasswd', [], '2001:db8:4c2:91::2')->assertNotFound();

        $this->assertSame('2001:db8:4c2:91::/64', $this->ban('2001:db8:4c2:91::1')['visitor']);
        $this->api('/ok', [], '2001:db8:4c2:91:1:2:3:4')->assertForbidden();

        // 相邻的 /64 是另一个访客
        $this->api('/ok', [], '2001:db8:4c2:92::1')->assertOk();
        $this->assertSame(1, static::$controllerRuns);
    }
}
