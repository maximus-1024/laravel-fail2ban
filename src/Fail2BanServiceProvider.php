<?php

namespace Maximus\Fail2Ban;

use Illuminate\Auth\Middleware\Authorize;
use Illuminate\Contracts\Auth\Access\Gate;
use Illuminate\Contracts\Foundation\CachesRoutes;
use Illuminate\Contracts\Http\Kernel;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\ServiceProvider;

class Fail2BanServiceProvider extends ServiceProvider
{
    use ServiceBindings;

    /**
     * Register any application services.
     */
    public function register(): void
    {
        $this->configure();
        $this->registerServices();
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        $this->authorization();
        $this->registerMiddleware();
        $this->registerRoutes();
        $this->registerResources();
        $this->offerPublishing();
        $this->registerCommands();
    }

    /**
     * 合并包自带的默认配置，并定义专用 Redis 连接（照 Horizon 的 configure()）。
     */
    protected function configure(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/fail2ban.php', 'fail2ban');

        Fail2Ban::use((string) config('fail2ban.redis.use', 'default'));
    }

    /**
     * 绑定存储契约（ServiceBindings：Contracts\*Repository => Repositories\Redis*Repository）。
     *
     * 实现只持有 Redis 管理器，用到时才取连接，所以解析它们不会连 Redis。
     */
    protected function registerServices(): void
    {
        foreach ($this->serviceBindings as $contract => $implementation) {
            $this->app->singleton($contract, $implementation);
        }

        // 规则入口：带上配置里追加、排除的清单条目与登记的自定义规则。
        // 解析时只实例化规则对象，清单文件与正则在第一次检测时才构建。
        $this->app->singleton(Inspector::class, fn ($app) => Inspector::fromConfig(
            (array) $app['config']->get('fail2ban', []), $app,
        ));
    }

    /**
     * 把 Http\Middleware\BlockBannedIps 加到全局中间件队列末尾。
     *
     * 全局队列的顺序是：prepend 的、框架默认的（含 TrustProxies）、append 的。排在末尾，
     * $request->ip() 才是 TrustProxies 处理过的访客地址，而不是代理地址。
     *
     * 宿主的 bootstrap/app.php 在 HTTP Kernel 被解析时才写入全局队列（afterResolving），
     * 所以 Kernel 还没解析时也登记成 afterResolving，排在它后面执行；命令行进程不会因此去解析 HTTP Kernel。
     */
    protected function registerMiddleware(): void
    {
        $push = function ($kernel) {
            if (method_exists($kernel, 'pushMiddleware')) {
                $kernel->pushMiddleware(Http\Middleware\BlockBannedIps::class);
            }
        };

        if ($this->app->resolved(Kernel::class)) {
            $push($this->app->make(Kernel::class));
        } else {
            $this->app->afterResolving(Kernel::class, $push);
        }
    }

    /**
     * 面板授权 viewFail2Ban：默认只允许本地环境（照 Horizon 的 viewHorizon，授权单独一步）。
     *
     * 宿主已经定义过就不覆盖；宿主在之后的服务提供者里 Gate::define() 会替换这里的默认值。
     * 参数允许为 null，未登录的访客在本地环境也能打开（与 Horizon 一致）。
     */
    protected function authorization(): void
    {
        $gate = $this->app->make(Gate::class);

        if (! $gate->has('viewFail2Ban')) {
            $gate->define('viewFail2Ban', fn ($user = null) => $this->app->environment('local'));
        }
    }

    /**
     * 注册面板页面与 {path}/api 接口路由，照 Horizon 的 registerRoutes()。
     *
     * 中间件依次是：Http\Middleware\RenderPanelExceptions（面板接口里的异常一律由扩展包渲染成带真实状态码的 JSON，
     * 必须排第一，后面的中间件抛的异常才经过它）、宿主配置的 fail2ban.panel.middleware（默认 web，
     * 含防跨站校验）、授权 can:viewFail2Ban。fail2ban.panel.domain 设了时只在那个域名下注册（照 Horizon 的 domain）。
     * panel.enabled 为 false 时不注册任何面板路由。
     */
    protected function registerRoutes(): void
    {
        if (! config('fail2ban.panel.enabled', true)) {
            return;
        }

        if ($this->app instanceof CachesRoutes && $this->app->routesAreCached()) {
            return;
        }

        Route::group([
            'domain' => config('fail2ban.panel.domain'),
            'prefix' => trim((string) config('fail2ban.panel.path', 'fail2ban'), '/'),
            'middleware' => [
                Http\Middleware\RenderPanelExceptions::class,
                ...(array) config('fail2ban.panel.middleware', ['web']),
                Authorize::using('viewFail2Ban'),
            ],
        ], function () {
            $this->loadRoutesFrom(__DIR__.'/../routes/web.php');
        });
    }

    /**
     * 注册页面模板，命名空间 fail2ban::。
     */
    protected function registerResources(): void
    {
        $this->loadViewsFrom(__DIR__.'/../resources/views', 'fail2ban');
    }

    /**
     * 可发布的资源。
     */
    protected function offerPublishing(): void
    {
        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__.'/../config/fail2ban.php' => config_path('fail2ban.php'),
            ], 'fail2ban-config');
        }
    }

    /**
     * 注册 fail2ban:unban、fail2ban:ban、fail2ban:mode：管理员自己被封、打不开面板时的出口。
     */
    protected function registerCommands(): void
    {
        if ($this->app->runningInConsole()) {
            $this->commands([
                Console\BanCommand::class,
                Console\ModeCommand::class,
                Console\UnbanCommand::class,
            ]);
        }
    }
}
