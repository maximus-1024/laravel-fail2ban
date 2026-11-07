<?php

namespace Maximus\Fail2Ban;

use Closure;
use Illuminate\Http\Request;

/**
 * 扩展包与宿主程序之间的接入点，写法照 Horizon::auth。
 *
 * 宿主程序在自己的服务提供者 boot() 里登记闭包；没登记时用包的默认行为。
 */
class Fail2Ban
{
    /**
     * 豁免规则：fn (string $ip, ?Request $request): bool
     *
     * @var \Closure|null
     */
    public static $exemptUsing;

    /**
     * 拒绝响应外形：替换包自带的 JSON 与页面。
     *
     * fn (\Illuminate\Http\Request $request, array $payload): mixed
     *
     * $payload = ['status' => int, 'message' => string, 'ip' => ?string, 'incident' => ?string, 'recorded_at' => ?string,
     * 'format' => 'html'|'json']，显示开关关掉的项为 null。format 说明按包的默认规则这次会给页面还是 JSON
     * （Accept 明确列出 text/html 才是 html），宿主可以据此给浏览器页面，例如渲染视图 fail2ban::blocked。返回值可以是路由能返回的任何东西；状态码一律按设置强制，
     * 并加 Cache-Control: no-store、X-Robots-Tag: noindex。见 Http\Responses\BlockedResponse。
     *
     * @var \Closure|null
     */
    public static $respondUsing;

    /**
     * 操作人：fn (?Request $request): ?string，用于面板与命令的操作日志。
     *
     * @var \Closure|null
     */
    public static $actorUsing;

    /**
     * 登记豁免规则。返回 true 的访客不会被自动或手动封禁。
     *
     * @return static
     */
    public static function exemptUsing(Closure $callback)
    {
        static::$exemptUsing = $callback;

        return new static;
    }

    /**
     * 登记拒绝响应外形。
     *
     * @return static
     */
    public static function respondUsing(Closure $callback)
    {
        static::$respondUsing = $callback;

        return new static;
    }

    /**
     * 登记操作人解析。
     *
     * @return static
     */
    public static function actorUsing(Closure $callback)
    {
        static::$actorUsing = $callback;

        return new static;
    }

    /**
     * 宿主是否豁免这个访客。默认没有豁免。
     *
     * 手动封禁来自命令行时没有请求对象，此时 $request 为 null。
     */
    public static function isExempt(string $ip, ?Request $request = null): bool
    {
        return static::$exemptUsing
            ? (bool) (static::$exemptUsing)($ip, $request)
            : false;
    }

    /**
     * 宿主登记的拒绝响应外形；null 表示使用包自带的响应。
     */
    public static function responder(): ?Closure
    {
        return static::$respondUsing;
    }

    /**
     * 操作日志里记的操作人。
     *
     * 依次取：宿主闭包的返回值、已登录用户的标识；都取不到时，
     * 没有请求对象（命令行）记 "console"，否则记 "unknown"。
     */
    public static function actor(?Request $request = null): string
    {
        $actor = static::$actorUsing ? (static::$actorUsing)($request) : null;

        if (blank($actor)) {
            $actor = $request?->user()?->getAuthIdentifier();
        }

        if (blank($actor)) {
            $actor = $request === null ? 'console' : 'unknown';
        }

        return (string) $actor;
    }

    /**
     * 专用 Redis 连接的持久连接标识：与宿主其它连接分开，持久连接池里的连接只给本包用。
     */
    public const PERSISTENT_ID = 'fail2ban';

    /**
     * 在运行时定义专用 Redis 连接 config('fail2ban.redis.connection')（照 Horizon::use()）。
     * 服务提供者在注册阶段调用，只写配置，不连 Redis。
     *
     * 宿主在 config/database.php 里已经定义了这个名字的连接（或集群）时原样使用，不覆盖。
     * 否则复制基础连接 $connection 的主机、端口、密码等参数（地址写在 url 里也认），并改成：
     *  - 持久连接，带固定的持久连接标识 PERSISTENT_ID。写在这个连接自己的 options 里：
     *    Laravel 会用全局的 database.redis.options 盖掉连接顶层的同名项（Laravel 12 的默认配置
     *    全局就有 persistent => false），只有连接自己的 options 排在全局之后；
     *  - 连接与读取超时取 fail2ban.redis.timeout，不重试（max_retries 为 0）；
     *  - 不带 database 键：配置里有它，Laravel 每次取连接（包括从持久连接池里取）都会多发一次
     *    SELECT。持久连接从不 SELECT，所以一直在 0 号库。要别的库就设 fail2ban.redis.database，
     *    代价是每个请求多一次往返。
     *  - 用户名与密码放进 context.auth，不留在 password、username 键上：Laravel 的 phpredis 连接器
     *    看到 password 就在每次建客户端时调用 auth()，持久连接从池里取出来也一样，每个请求多一次 AUTH 往返；
     *    放在 context.auth 里由 phpredis 在真正新建 TCP 连接时认证一次（phpredis 5.3 起支持）。
     * 全局键前缀（database.redis.options.prefix）照常生效。
     *
     * 基础连接也没定义时什么都不做：用到时 Redis 管理器报「连接未配置」，中间件按读取失败放行。
     */
    public static function use(string $connection): void
    {
        $name = (string) config('fail2ban.redis.connection', 'fail2ban');

        if (config("database.redis.{$name}") !== null || config("database.redis.clusters.{$name}") !== null) {
            return;
        }

        $base = config("database.redis.clusters.{$connection}.0") ?? config("database.redis.{$connection}");

        if (! is_array($base)) {
            return;
        }

        $config = (new \Illuminate\Support\ConfigurationUrlParser)->parseConfiguration($base);

        unset($config['database']);

        if (filled($password = $config['password'] ?? null)) {
            $config['context'] = array_merge((array) ($config['context'] ?? []), [
                'auth' => filled($config['username'] ?? null) ? [(string) $config['username'], (string) $password] : $password,
            ]);
        }

        unset($config['password'], $config['username']);

        if (filled($database = config('fail2ban.redis.database'))) {
            $config['database'] = (int) $database;
        }

        $timeout = (float) config('fail2ban.redis.timeout', 0.2);

        $config['options'] = array_merge((array) ($config['options'] ?? []), [
            'persistent' => true,
            'persistent_id' => static::PERSISTENT_ID,
            'timeout' => $timeout,
            'read_timeout' => $timeout,
            'max_retries' => 0,
        ]);

        config(["database.redis.{$name}" => $config]);
    }

    /**
     * 清空所有已登记的闭包（测试用）。
     */
    public static function flush(): void
    {
        static::$exemptUsing = null;
        static::$respondUsing = null;
        static::$actorUsing = null;
    }

    /**
     * 面板的样式：读出 dist/app.css 内联进外壳页面（照 Horizon::css()）。
     *
     * @return \Illuminate\Contracts\Support\Htmlable
     */
    public static function css()
    {
        if (($css = @file_get_contents(__DIR__.'/../dist/app.css')) === false) {
            throw new \RuntimeException('Unable to load the Fail2Ban panel CSS.');
        }

        // 防御：内容里万一出现结束标签，不能提前关掉 <style>。
        $css = str_ireplace('</style', '<\/style', $css);

        return new \Illuminate\Support\HtmlString("<style>{$css}</style>");
    }

    /**
     * 面板的脚本：读出 dist/app.js 内联进外壳页面（照 Horizon::js()）。
     *
     * 产物是立即执行的 iife，所以必须放在 <div id="app"> 之后。
     *
     * @return \Illuminate\Contracts\Support\Htmlable
     */
    public static function js()
    {
        if (($js = @file_get_contents(__DIR__.'/../dist/app.js')) === false) {
            throw new \RuntimeException('Unable to load the Fail2Ban panel JavaScript.');
        }

        // 防御：字符串里的 "</script" 会提前关掉 <script>；"<\/script" 在 JS 里等价。
        $js = str_ireplace('</script', '<\/script', $js);

        return new \Illuminate\Support\HtmlString("<script>{$js}</script>");
    }
}
