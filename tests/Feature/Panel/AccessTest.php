<?php

namespace Maximus\Fail2Ban\Tests\Feature\Panel;

use Illuminate\Foundation\Auth\User;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\Route;
use Orchestra\Testbench\Attributes\DefineEnvironment;
use PHPUnit\Framework\Attributes\Test;

/**
 * 未登录或未授权的人访问面板页面与接口都被拒绝；改动类请求缺防跨站令牌时被拒绝；
 * panel.enabled 为 false 时面板路由不存在。
 */
class AccessTest extends PanelTestCase
{
    /**
     * 面板页面与每一组接口（方法、地址）。
     */
    protected function endpoints(): array
    {
        return [
            ['GET', '/fail2ban'],
            ['GET', '/fail2ban/bans'],
            ['GET', '/fail2ban/api/overview'],
            ['GET', '/fail2ban/api/incidents'],
            ['GET', '/fail2ban/api/incidents/BAN-20261107-AAAAAA'],
            ['GET', '/fail2ban/api/bans'],
            ['POST', '/fail2ban/api/bans'],
            ['DELETE', '/fail2ban/api/bans?visitor=203.0.113.9'],
            ['GET', '/fail2ban/api/allowlist'],
            ['POST', '/fail2ban/api/allowlist'],
            ['DELETE', '/fail2ban/api/allowlist?entry=203.0.113.9'],
            ['GET', '/fail2ban/api/settings'],
            ['PUT', '/fail2ban/api/settings'],
            ['GET', '/fail2ban/api/audit'],
        ];
    }

    /**
     * 宿主把面板接到自己的登录中间件上。
     */
    protected function useLoginMiddleware($app): void
    {
        $app['config']->set('fail2ban.panel.middleware', ['web', 'auth']);
    }

    protected function disablePanel($app): void
    {
        $app['config']->set('fail2ban.panel.enabled', false);
    }

    #[Test]
    #[DefineEnvironment('useLoginMiddleware')]
    public function guests_are_rejected_by_the_host_login_middleware_on_every_endpoint(): void
    {
        Route::get('/login', fn () => 'login')->name('login');

        foreach ($this->endpoints() as [$method, $uri]) {
            $this->json($method, $uri, ['ip' => '203.0.113.9', 'minutes' => 10, 'note' => 'x', 'entry' => '203.0.113.9'])
                ->assertStatus(401);
        }

        $this->get('/fail2ban')->assertRedirect('/login');

        $this->assertSame(0, $this->auditCount());
        $this->assertSame([], app(\Maximus\Fail2Ban\Contracts\BanRepository::class)->all());
    }

    #[Test]
    #[DefineEnvironment('useLoginMiddleware')]
    public function logged_in_users_without_the_gate_are_forbidden_on_every_endpoint(): void
    {
        Gate::define('viewFail2Ban', fn ($user) => $user->email === 'boss@example.com');

        $user = (new User)->forceFill(['id' => 1, 'email' => 'intern@example.com']);

        foreach ($this->endpoints() as [$method, $uri]) {
            $this->actingAs($user)
                ->json($method, $uri, ['ip' => '203.0.113.9', 'minutes' => 10, 'note' => 'x', 'entry' => '203.0.113.9'])
                ->assertForbidden();
        }

        $this->assertSame(0, $this->auditCount());

        $boss = (new User)->forceFill(['id' => 2, 'email' => 'boss@example.com']);
        $this->actingAs($boss)->getJson('/fail2ban/api/overview')->assertOk();
        $this->actingAs($boss)->get('/fail2ban')->assertOk();
    }

    #[Test]
    public function mutating_requests_without_a_csrf_token_are_rejected(): void
    {
        // 单元测试环境下框架会跳过防跨站校验，换成生产环境才是真实行为。
        $this->app['env'] = 'production';

        $requests = [
            ['POST', '/fail2ban/api/bans', ['ip' => '203.0.113.9', 'minutes' => 10, 'note' => 'x']],
            ['DELETE', '/fail2ban/api/bans?visitor=203.0.113.9', []],
            ['POST', '/fail2ban/api/allowlist', ['entry' => '198.51.100.7', 'note' => 'x']],
            ['DELETE', '/fail2ban/api/allowlist?entry=198.51.100.7', []],
            ['PUT', '/fail2ban/api/settings', ['mode' => 'block']],
        ];

        foreach ($requests as [$method, $uri, $body]) {
            $this->withSession(['_token' => 'right-token'])
                ->json($method, $uri, $body)
                ->assertStatus(419);

            $this->withSession(['_token' => 'right-token'])
                ->json($method, $uri, $body, ['X-CSRF-TOKEN' => 'wrong-token'])
                ->assertStatus(419);
        }

        $this->assertSame(0, $this->auditCount(), '被拒绝的请求不应留下任何改动');
        $this->assertSame('observe', app(\Maximus\Fail2Ban\Contracts\SettingsRepository::class)->all()['mode']);

        // 带上正确的令牌就能通过。
        $this->withSession(['_token' => 'right-token'])
            ->putJson('/fail2ban/api/settings', ['mode' => 'block'], ['X-CSRF-TOKEN' => 'right-token'])
            ->assertOk();

        $this->assertSame('block', app(\Maximus\Fail2Ban\Contracts\SettingsRepository::class)->all()['mode']);
    }

    #[Test]
    #[DefineEnvironment('disablePanel')]
    public function no_panel_routes_exist_when_the_panel_is_disabled(): void
    {
        foreach (Route::getRoutes() as $route) {
            $this->assertStringStartsNotWith('fail2ban', $route->uri(), "不应注册 {$route->uri()}");
        }

        $this->get('/fail2ban')->assertNotFound();
        $this->getJson('/fail2ban/api/overview')->assertNotFound();
        $this->postJson('/fail2ban/api/bans', ['ip' => '203.0.113.9', 'minutes' => 10, 'note' => 'x'])->assertNotFound();
    }
}
