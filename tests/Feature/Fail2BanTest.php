<?php

namespace Maximus\Fail2Ban\Tests\Feature;

use Illuminate\Http\Request;
use Maximus\Fail2Ban\Fail2Ban;
use Maximus\Fail2Ban\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;

/**
 * 入口类 Fail2Ban 的三个接入点（豁免、拒绝响应外形、操作人），与包自带配置的合并和发布。
 */
class Fail2BanTest extends TestCase
{
    #[Test]
    public function config_is_merged_with_defaults(): void
    {
        $this->assertFalse(config('fail2ban.enabled'));
        $this->assertSame('observe', config('fail2ban.mode'));

        $this->assertSame(
            ['not-found-scan', 'sensitive-path', 'scanner-agent', 'attack-pattern', 'known-exploit'],
            array_keys(config('fail2ban.rules'))
        );
        $this->assertSame(
            ['action' => 'ban', 'window' => 5, 'count' => 10, 'ban' => 30],
            config('fail2ban.rules.not-found-scan')
        );
        $this->assertSame(
            ['action' => 'ban', 'window' => 1, 'count' => 5, 'ban' => 60],
            config('fail2ban.rules.attack-pattern')
        );

        $this->assertSame(
            ['enabled' => true, 'factor' => 2, 'max_days' => 7, 'keep_days' => 7],
            config('fail2ban.repeat')
        );
        $this->assertSame(403, config('fail2ban.response.status'));
        $this->assertSame(500, config('fail2ban.history_limit'));
        $this->assertSame(30, config('fail2ban.stats_days'));
        $this->assertSame(100, config('fail2ban.hits_max'));
        $this->assertSame(120, config('fail2ban.path_max'));
        $this->assertSame('fail2ban', config('fail2ban.redis.connection'));
        $this->assertSame(0.2, config('fail2ban.redis.timeout'));
        $this->assertSame('fail2ban', config('fail2ban.panel.path'));
        $this->assertContains('104.16.0.0/13', config('fail2ban.allowlist.builtin.cloudflare'));
        $this->assertSame([], config('fail2ban.allowlist.extra'));
    }

    #[Test]
    public function config_can_be_published(): void
    {
        $target = config_path('fail2ban.php');
        @unlink($target);

        try {
            $this->artisan('vendor:publish', ['--tag' => 'fail2ban-config'])->assertSuccessful();

            $this->assertFileExists($target);
            $this->assertFileEquals(__DIR__.'/../../config/fail2ban.php', $target);
        } finally {
            @unlink($target);
        }
    }

    #[Test]
    public function exempt_callback_can_be_registered_and_read(): void
    {
        $this->assertFalse(Fail2Ban::isExempt('203.0.113.7'));

        Fail2Ban::exemptUsing(fn (string $ip, ?Request $request) => $ip === '203.0.113.7');

        $this->assertTrue(Fail2Ban::isExempt('203.0.113.7'));
        $this->assertFalse(Fail2Ban::isExempt('203.0.113.8', Request::create('/')));
    }

    #[Test]
    public function respond_callback_can_be_registered_and_read(): void
    {
        $this->assertNull(Fail2Ban::responder());

        $callback = fn () => 'custom';
        Fail2Ban::respondUsing($callback);

        $this->assertSame($callback, Fail2Ban::responder());
    }

    #[Test]
    public function actor_callback_can_be_registered_and_read(): void
    {
        $this->assertSame('console', Fail2Ban::actor());
        $this->assertSame('unknown', Fail2Ban::actor(Request::create('/')));

        Fail2Ban::actorUsing(fn (?Request $request) => 'admin');

        $this->assertSame('admin', Fail2Ban::actor(Request::create('/')));
    }
}
