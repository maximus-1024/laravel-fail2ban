<?php

namespace Maximus\Fail2Ban\Http\Middleware;

use Closure;
use Illuminate\Contracts\Container\Container;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use InvalidArgumentException;
use Maximus\Fail2Ban\Contracts\AllowlistRepository;
use Maximus\Fail2Ban\Contracts\BanRepository;
use Maximus\Fail2Ban\Enforcer;
use Maximus\Fail2Ban\Fail2Ban;
use Maximus\Fail2Ban\Http\Responses\BlockedResponse;
use Maximus\Fail2Ban\Inspector;
use Maximus\Fail2Ban\Visitor;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

/**
 * 全局可终止中间件。由服务提供者加到全局队列末尾，排在 TrustProxies 之后。
 *
 * 进入（业务路径，越轻越好）：
 *  - 总开关关闭：直接放行，不解析任何仓库，不发 Redis 命令；
 *  - 否则恰好一次 Redis 往返（BanRepository::lookup()）同时取封禁键与运行设置，
 *    结果放进 $request->attributes[self::ATTRIBUTE]，收尾阶段从那里取、不再重读；
 *  - 读取失败（异常、超时）：记警告并放行，收尾整个跳过；
 *  - 命中的是 IPv6 网段的封禁键时，再按真实地址查白名单与宿主豁免，通过就放行（多一次往返，见 spared()）；
 *  - 模式为拦截且有封禁：在路由之前返回拒绝响应。
 *
 * 收尾（响应已发出）：
 *  - 被拦的请求、观察模式下有封禁的请求：只记被拦次数与统计；
 *  - 其余先在进程内做规则检测，没有命中就返回——这条路上不发任何 Redis 命令；
 *  - 有命中才交给 Enforcer（白名单、记命中、封禁）。
 *  - 任何异常都吞掉并记日志。
 *
 * 状态只放在请求对象上，不放在中间件实例上：收尾时框架会解析一个新实例，常驻进程里实例也可能被复用。
 */
class BlockBannedIps
{
    /**
     * 请求属性名：进入阶段的结果。
     */
    public const ATTRIBUTE = 'fail2ban';

    /**
     * 进入阶段的结果（ATTRIBUTE 里的 state）。
     */
    public const FAILED = 'failed';     // 读 Redis 失败，已放行，收尾跳过

    public const OFF = 'off';           // 模式为已关闭，收尾跳过

    public const BLOCKED = 'blocked';   // 模式为拦截且有封禁，已拒绝

    public const BANNED = 'banned';     // 模式为观察且有封禁，已放行（本应拦截）

    public const CLEAN = 'clean';       // 没有封禁，已放行，收尾做规则检测

    /**
     * Create a new middleware instance.
     */
    public function __construct(
        protected Container $container,
    ) {
    }

    /**
     * Handle an incoming request.
     */
    public function handle(Request $request, Closure $next): Response
    {
        if (! $this->container->make('config')->get('fail2ban.enabled')) {
            return $next($request);
        }

        try {
            $visitor = Visitor::key((string) $request->ip());
        } catch (InvalidArgumentException) {
            return $next($request);
        }

        try {
            ['ban' => $ban, 'settings' => $settings] = $this->container->make(BanRepository::class)->lookup($visitor);

            // IPv6 的封禁键是整个 64 位网段，同一个网段里可能是不同的客户（有的云厂商让多个客户共用一个 /64）。
            // 白名单与宿主豁免按这次请求的真实地址判断：任一通过就当作没有封禁放行，不计被拦次数。
            // 只有命中的是网段封禁键才查；IPv4 的封禁键就是地址本身，正常请求（没有封禁键）都不走这里。
            if ($ban !== null && $settings['mode'] !== 'off' && str_ends_with($visitor, '/64') && $this->spared($request)) {
                $ban = null;
            }
        } catch (Throwable $e) {
            Log::warning('fail2ban: 读取封禁状态失败，本次请求放行。', [
                'ip' => $request->ip(),
                'exception' => $e->getMessage(),
            ]);

            $request->attributes->set(self::ATTRIBUTE, ['state' => self::FAILED]);

            return $next($request);
        }

        $state = match (true) {
            $settings['mode'] === 'off' => self::OFF,
            $ban === null => self::CLEAN,
            $settings['mode'] === 'block' => self::BLOCKED,
            default => self::BANNED,
        };

        $request->attributes->set(self::ATTRIBUTE, [
            'state' => $state,
            'visitor' => $visitor,
            'ban' => $ban,
            'settings' => $settings,
        ]);

        if ($state === self::BLOCKED) {
            return BlockedResponse::make($request, $ban, $settings['response'])->toResponse($request);
        }

        return $next($request);
    }

    /**
     * Handle tasks after the response has been sent to the browser.
     */
    public function terminate(Request $request, Response $response): void
    {
        $entry = $request->attributes->get(self::ATTRIBUTE);

        if (! is_array($entry) || ! in_array($entry['state'] ?? null, [self::CLEAN, self::BLOCKED, self::BANNED], true)) {
            return;
        }

        try {
            if ($entry['state'] !== self::CLEAN) {
                $this->container->make(Enforcer::class)->blocked($entry['visitor']);

                return;
            }

            $hits = $this->container->make(Inspector::class)->inspect(
                $request, $response, array_map(fn ($rule) => $rule['action'] ?? 'off', $entry['settings']['rules'])
            );

            if ($hits === []) {
                return;
            }

            $this->container->make(Enforcer::class)->handle($request, $entry['visitor'], $hits, $entry['settings']);
        } catch (Throwable $e) {
            // 这里吞掉的异常意味着本次请求的检测与封禁没有完成（例如宿主绑定的类型不对、Redis 超时），
            // 日志正文里直接写出异常类与消息，不翻上下文也能看出是什么问题。
            try {
                Log::error(sprintf('fail2ban: 收尾阶段出错，本次请求的检测与封禁没有完成：%s: %s', $e::class, $e->getMessage()), [
                    'ip' => $request->ip(),
                    'exception' => $e,
                ]);
            } catch (Throwable) {
                // 日志也写不了时退到 PHP 自己的错误日志，不能影响后续请求。
                error_log(sprintf('fail2ban: 收尾阶段出错：%s: %s', $e::class, $e->getMessage()));
            }
        }
    }

    /**
     * 这次请求的真实地址在白名单里，或被宿主豁免（地址交给宿主前先规范化）。
     *
     * 白名单先查配置里的内置段（不碰 Redis），再查面板条目（一次往返）；宿主豁免是宿主自己的闭包。
     */
    protected function spared(Request $request): bool
    {
        $ip = Visitor::ip((string) $request->ip());

        return $this->container->make(AllowlistRepository::class)->match($ip) !== null
            || Fail2Ban::isExempt($ip, $request);
    }
}
