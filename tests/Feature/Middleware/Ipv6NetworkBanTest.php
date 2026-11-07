<?php

namespace Maximus\Fail2Ban\Tests\Feature\Middleware;

use Maximus\Fail2Ban\Contracts\AllowlistRepository;
use Maximus\Fail2Ban\Contracts\AuditRepository;
use Maximus\Fail2Ban\Fail2Ban;
use Maximus\Fail2Ban\Operations;
use Maximus\Fail2Ban\Visitor;
use PHPUnit\Framework\Attributes\Test;

/**
 * IPv6 按 64 位网段封禁，但白名单与宿主豁免按这次请求的真实地址判断。
 *
 * 同网段的邻居触发了封禁，白名单里的单个地址、宿主豁免的地址照常放行，也不计被拦次数；
 * 同网段的其它地址照常被拦。IPv4 的封禁键就是地址本身，不受影响。
 */
class Ipv6NetworkBanTest extends MiddlewareTestCase
{
    private const ALLOWED = '2001:db8:4c2:91::5';

    private const NEIGHBOUR = '2001:db8:4c2:91::6';

    private const OTHER = '2001:db8:4c2:91::7';

    #[Test]
    public function an_allowlisted_address_passes_when_a_neighbour_got_its_network_banned(): void
    {
        $this->setMode('block');
        $this->app->make(AllowlistRepository::class)->add(self::ALLOWED, '办公室', 'admin');

        // 邻居请求一次即封的利用地址，整个 /64 被封
        $this->api('/_ignition/execute-solution', [], self::NEIGHBOUR)->assertNotFound();
        $this->assertSame('2001:db8:4c2:91::/64', $this->ban(self::NEIGHBOUR)['visitor']);

        $runs = static::$controllerRuns;
        $this->api('/ok', [], self::ALLOWED)->assertOk();
        $this->assertSame($runs + 1, static::$controllerRuns);

        // 同网段的其它地址照常被拦
        $this->api('/ok', [], self::OTHER)->assertForbidden();
        $this->api('/ok', [], self::NEIGHBOUR)->assertForbidden();

        // 放行的那次不计被拦次数
        $this->assertSame(2, $this->ban(self::NEIGHBOUR)['blocked']);
    }

    #[Test]
    public function an_allowlisted_address_passes_when_a_neighbour_was_banned_manually(): void
    {
        $this->setMode('block');
        $this->app->make(AllowlistRepository::class)->add(self::ALLOWED, '办公室', 'admin');

        $this->app->make(Operations::class)->ban(self::OTHER, 60, '人工', 'admin', AuditRepository::VIA_PANEL);

        $this->api('/ok', [], self::ALLOWED)->assertOk();
        $this->api('/ok', [], self::NEIGHBOUR)->assertForbidden();
    }

    #[Test]
    public function a_host_exempted_address_passes_and_receives_the_normalised_address(): void
    {
        $this->setMode('block');

        $asked = [];
        Fail2Ban::exemptUsing(function (string $ip) use (&$asked) {
            $asked[] = $ip;

            return $ip === self::ALLOWED;
        });

        $this->bans()->banManually(Visitor::key(self::NEIGHBOUR), ['incident' => 'BAN-20261107-AAAAAA', 'operator' => 't'], 10);

        // 写法不同（大写、补零）也按规范化后的地址交给宿主
        $this->api('/ok', [], '2001:DB8:4C2:91:0:0:0:5')->assertOk();
        $this->api('/ok', [], self::NEIGHBOUR)->assertForbidden();

        $this->assertSame([self::ALLOWED, self::NEIGHBOUR], $asked);
        $this->assertSame(1, $this->ban(self::NEIGHBOUR)['blocked']);
    }

    #[Test]
    public function in_observe_mode_an_allowlisted_address_in_a_banned_network_is_not_counted_as_blocked(): void
    {
        $this->setMode('observe');
        $this->app->make(AllowlistRepository::class)->add(self::ALLOWED, '办公室', 'admin');

        $this->bans()->banManually(Visitor::key(self::NEIGHBOUR), ['incident' => 'BAN-20261107-AAAAAA', 'operator' => 't'], 10);

        $this->api('/ok', [], self::ALLOWED)->assertOk();
        $this->assertSame(0, $this->ban(self::NEIGHBOUR)['blocked']);

        $this->api('/ok', [], self::OTHER)->assertOk();
        $this->assertSame(1, $this->ban(self::NEIGHBOUR)['blocked']);
    }

    #[Test]
    public function an_allowlisted_address_in_a_banned_network_is_still_never_recorded(): void
    {
        $this->setMode('block');
        $this->app->make(AllowlistRepository::class)->add(self::ALLOWED, '办公室', 'admin');
        $this->bans()->banManually(Visitor::key(self::NEIGHBOUR), ['incident' => 'BAN-20261107-AAAAAA', 'operator' => 't'], 10);

        $this->api('/.env', [], self::ALLOWED)->assertNotFound();

        $this->assertSame([], $this->hitCounts(self::ALLOWED));
    }
}
