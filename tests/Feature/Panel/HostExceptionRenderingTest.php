<?php

namespace Maximus\Fail2Ban\Tests\Feature\Panel;

use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Foundation\Auth\User;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\Route;
use Maximus\Fail2Ban\Contracts\StatsRepository;
use Orchestra\Testbench\Attributes\DefineEnvironment;
use PHPUnit\Framework\Attributes\Test;
use RuntimeException;
use Throwable;

/**
 * 宿主把所有异常渲染成「HTTP 200 加业务码」，面板接口的 401、403、419、422、500
 * 仍按约定的 JSON 与真实状态码返回——面板接口里的异常一律由扩展包渲染，上报仍交给宿主。
 * 面板以外的路由与面板外壳页面，照旧交给宿主渲染。
 */
class HostExceptionRenderingTest extends PanelTestCase
{
    /**
     * 宿主的异常处理被调用渲染的次数。
     */
    private int $hostRendered = 0;

    /**
     * 宿主的异常处理收到的上报。
     *
     * @var list<\Throwable>
     */
    private array $hostReported = [];

    protected function setUp(): void
    {
        parent::setUp();

        $this->app->make(ExceptionHandler::class)->renderable(function (Throwable $e) {
            $this->hostRendered++;

            return response()->json(['code' => 50000, 'message' => '系统错误'], 200);
        });

        $this->app->make(ExceptionHandler::class)->reportable(function (Throwable $e) {
            $this->hostReported[] = $e;
        });

        Route::middleware('web')->get('/host/boom', fn () => throw new RuntimeException('boom'));
    }

    protected function useLoginMiddleware($app): void
    {
        $app['config']->set('fail2ban.panel.middleware', ['web', 'auth']);
    }

    #[Test]
    public function validation_errors_are_422_with_the_field_errors(): void
    {
        $this->postJson($this->api('/bans'), ['ip' => 'nope', 'minutes' => 10, 'note' => 'x'])
            ->assertStatus(422)
            ->assertJsonStructure(['message', 'errors' => ['ip']]);

        $this->putJson($this->api('/settings'), ['rules' => [['id' => 'not-found-scan', 'count' => 0]]])
            ->assertStatus(422)
            ->assertJsonStructure(['message', 'errors' => ['rules.0.count']]);

        $this->assertSame(0, $this->hostRendered);
    }

    #[Test]
    public function an_unauthorized_user_gets_403(): void
    {
        Gate::define('viewFail2Ban', fn ($user = null) => false);

        $this->getJson($this->api('/overview'))->assertForbidden()->assertJsonStructure(['message']);
        $this->assertSame(0, $this->hostRendered);
    }

    #[Test]
    #[DefineEnvironment('useLoginMiddleware')]
    public function a_guest_gets_401_from_a_login_middleware_that_throws(): void
    {
        Route::get('/login', fn () => 'login')->name('login');

        $this->getJson($this->api('/overview'))->assertUnauthorized()->assertJsonStructure(['message']);
        $this->get($this->api('/overview'))->assertUnauthorized();
        $this->assertSame(0, $this->hostRendered);

        $this->actingAs((new User)->forceFill(['id' => 1]))->getJson($this->api('/overview'))->assertOk();
    }

    #[Test]
    public function a_missing_csrf_token_gets_419(): void
    {
        $this->app['env'] = 'production';

        $this->withSession(['_token' => 'right-token'])
            ->putJson($this->api('/settings'), ['mode' => 'block'])
            ->assertStatus(419);

        $this->assertSame(0, $this->hostRendered);
    }

    #[Test]
    public function a_server_error_is_500_json_and_still_reported_to_the_host(): void
    {
        $this->mock(StatsRepository::class)->shouldReceive('trend')->andThrow(new RuntimeException('统计坏了'));

        config(['app.debug' => false]);

        $this->getJson($this->api('/overview'))
            ->assertStatus(500)
            ->assertExactJson(['message' => 'Server Error']);

        // 浏览器式的请求（不要求 JSON）也给 JSON
        $this->get($this->api('/overview'))->assertStatus(500)->assertJson(['message' => 'Server Error']);

        config(['app.debug' => true]);

        $this->getJson($this->api('/overview'))
            ->assertStatus(500)
            ->assertJsonPath('message', '统计坏了')
            ->assertJsonPath('exception', RuntimeException::class);

        $this->assertSame(0, $this->hostRendered, '宿主没有参与渲染');
        $this->assertCount(3, $this->hostReported, '每次都上报给了宿主');
        $this->assertSame('统计坏了', $this->hostReported[0]->getMessage());
    }

    #[Test]
    public function other_routes_and_the_shell_page_still_use_the_host_handler(): void
    {
        $this->getJson('/host/boom')->assertOk()->assertJson(['code' => 50000]);
        $this->assertSame(1, $this->hostRendered);

        Gate::define('viewFail2Ban', fn ($user = null) => false);
        $this->get('/fail2ban')->assertOk()->assertJson(['code' => 50000]);
        $this->assertSame(2, $this->hostRendered);

        // 面板请求结束后，宿主的异常处理原样恢复
        $this->assertNotInstanceOf(\Maximus\Fail2Ban\Http\PanelExceptionHandler::class, $this->app->make(ExceptionHandler::class));
    }
}
