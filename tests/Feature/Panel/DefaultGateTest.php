<?php

namespace Maximus\Fail2Ban\Tests\Feature\Panel;

use Illuminate\Support\Facades\Gate;
use Maximus\Fail2Ban\Fail2BanServiceProvider;
use PHPUnit\Framework\Attributes\Test;

/**
 * 授权 viewFail2Ban 默认只允许本地环境（照 Horizon），宿主可以重新定义。
 * 这里不放开授权（openGate = false）。
 */
class DefaultGateTest extends PanelTestCase
{
    protected bool $openGate = false;

    #[Test]
    public function the_default_gate_only_allows_the_local_environment(): void
    {
        $this->assertSame('testing', $this->app->environment());

        $this->get('/fail2ban')->assertForbidden();
        $this->getJson('/fail2ban/api/overview')->assertForbidden();
        $this->getJson('/fail2ban/api/settings')->assertForbidden();
        $this->postJson('/fail2ban/api/bans', ['ip' => '203.0.113.9', 'minutes' => 10, 'note' => 'x'])->assertForbidden();

        $this->app['env'] = 'local';

        $this->get('/fail2ban')->assertOk();
        $this->getJson('/fail2ban/api/overview')->assertOk();
    }

    #[Test]
    public function the_host_can_redefine_the_gate(): void
    {
        $this->app['env'] = 'local';

        Gate::define('viewFail2Ban', fn ($user = null) => false);

        $this->getJson('/fail2ban/api/overview')->assertForbidden();
    }

    #[Test]
    public function a_gate_defined_by_the_host_before_the_package_boots_is_kept(): void
    {
        Gate::define('viewFail2Ban', fn ($user = null) => false);

        // 再跑一次包的定义，模拟宿主的服务提供者先启动。
        (fn () => $this->authorization())->call($this->app->getProvider(Fail2BanServiceProvider::class));

        $this->app['env'] = 'local';

        $this->getJson('/fail2ban/api/overview')->assertForbidden();
    }
}
