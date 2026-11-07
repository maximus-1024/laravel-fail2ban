<?php

namespace Maximus\Fail2Ban\Tests\Feature\Middleware;

use Illuminate\Validation\ValidationException;
use Maximus\Fail2Ban\Contracts\AuditRepository;
use Maximus\Fail2Ban\Fail2Ban;
use Maximus\Fail2Ban\Operations;
use PHPUnit\Framework\Attributes\Test;

/**
 * 交给宿主豁免回调的是规范化之后的地址。IPv4 映射的 IPv6（::ffff:1.2.3.4）
 * 按 IPv4 交出去，宿主按 IPv4 登记的服务器地址才能对上。自动封禁与手动封禁两处都是。
 */
class ExemptCallbackAddressTest extends MiddlewareTestCase
{
    private const MAPPED = '::ffff:203.0.113.47';

    #[Test]
    public function the_automatic_ban_flow_asks_the_host_with_the_ipv4_address(): void
    {
        $this->setMode('block');

        $asked = [];
        Fail2Ban::exemptUsing(function (string $ip) use (&$asked) {
            $asked[] = $ip;

            return $ip === self::IP;
        });

        $this->api('/_ignition/execute-solution', [], self::MAPPED)->assertNotFound();

        $this->assertSame([self::IP], $asked);
        $this->assertNull($this->ban(self::IP), '宿主按 IPv4 豁免了它，不应被封');
    }

    #[Test]
    public function a_manual_ban_asks_the_host_with_the_ipv4_address(): void
    {
        $asked = [];
        Fail2Ban::exemptUsing(function (string $ip) use (&$asked) {
            $asked[] = $ip;

            return $ip === self::IP;
        });

        try {
            $this->app->make(Operations::class)->ban(self::MAPPED, 60, '人工', 'admin', AuditRepository::VIA_PANEL);
            $this->fail('宿主豁免的地址不应能被手动封禁');
        } catch (ValidationException $e) {
            $this->assertArrayHasKey('ip', $e->errors());
        }

        $this->assertSame([self::IP], $asked);
        $this->assertNull($this->ban(self::IP));
    }
}
