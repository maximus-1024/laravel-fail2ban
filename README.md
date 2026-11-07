# maximus-1024/laravel-fail2ban

Laravel 扩展包：类似 fail2ban 的「异常访问自动封禁」中间件与管理面板，数据存放在专用 Redis 连接中。

## 当前状态

开发中。包含：全局中间件（进入时一次 Redis 往返查封禁，检测在响应发出之后做）、五条内置规则、
封禁流程、管理面板与三个命令（`fail2ban:unban`、`fail2ban:ban`、`fail2ban:mode`）。总开关
`FAIL2BAN_ENABLED` 默认开启，运行模式默认是观察：安装后只统计和记录，不拦截任何请求，确认无误后再切到拦截模式。
总开关关闭时中间件不做任何事、不连 Redis。

## 要求

- PHP 8.2+，Laravel 12
- Redis，客户端**必须是 phpredis 扩展**（`database.redis.client` 为 `phpredis`）。扩展包用到了 phpredis 的持久连接、
  `context.auth` 与管道里的脚本调用，不支持 predis

## 安装

```bash
composer require maximus-1024/laravel-fail2ban
php artisan vendor:publish --tag=fail2ban-config
```

### Redis 连接

**不用在 `config/database.php` 里写专用连接。** 扩展包在注册阶段（只写配置，不连 Redis）用一个基础连接的
主机、端口、密码，定义出名为 `fail2ban` 的专用连接（写法照 Horizon 的 `Horizon::use()`）：

- 持久连接，带固定的持久连接标识 `fail2ban`，同一个 php-fpm 进程的后续请求复用同一条 TCP 连接；
- 连接与读取超时取 `FAIL2BAN_REDIS_TIMEOUT`（默认 0.2 秒），不重试；超时或出错时本次请求放行；
- 不选库：一直用 0 号库，省掉每个请求一次 `SELECT` 往返；
- 全局键前缀（`database.redis.options.prefix`，例如 `app_`）照常生效，键形如 `app_fail2ban:ban:…`。

**在 Cloudflare 等反向代理后面部署时**，请先配置好 Laravel 的 `TrustProxies`，让 `$request->ip()` 返回访客的真实地址：
扩展包按这个地址计数和封禁，配错了会把代理自己的地址封掉，等于封了所有人。内置白名单默认已包含 Cloudflare 的地址段。

| 环境变量 | 默认 | 说明 |
| --- | --- | --- |
| `FAIL2BAN_REDIS_USE` | `default` | 基础连接名，取它的主机、端口、用户名、密码（写在 `url` 里也认）。它的库号、重试设置不沿用 |
| `FAIL2BAN_REDIS_DATABASE` | 不指定 | 要放在别的库时填库号。代价是每个请求多一次 `SELECT` 往返 |
| `FAIL2BAN_REDIS_TIMEOUT` | `0.2` | 连接与读取超时，秒 |
| `FAIL2BAN_REDIS_CONNECTION` | `fail2ban` | 专用连接名 |

宿主在 `config/database.php` 里**已经定义了**同名连接时，扩展包原样使用、不覆盖。这时请自己把
`persistent`、`persistent_id`、`timeout`、`read_timeout` 写在这个连接自己的 `options` 里：Laravel 12 会用全局
`database.redis.options` 盖掉连接顶层的同名项（默认配置的全局 options 里就有 `persistent => false`），
写在顶层的 `persistent` 不生效；连接里有 `database` 键时，Laravel 每次取连接都会发一次 `SELECT`。

### 服务器上的 PHP 设置

- **opcache 要开**（php-fpm 生产环境默认就开）。三份内置清单预先编译成 `resources/rules/compiled.php`，
  opcache 把它放在共享内存里，每个请求取用几乎不花时间；不开 opcache 时每个请求都要重新编译这个文件。
- **`redis.pconnect.echo_check_liveness`**（phpredis 的全局设置，默认 1）：从持久连接池取连接时先发一次 `ECHO`
  检查连接是否还活着。关掉（`redis.pconnect.echo_check_liveness=0`）后，正常请求在业务路径上只剩扩展包自己的
  那一次往返（实测：默认 2 次，关掉后 1 次）。代价：池里的连接已经断了而本机没察觉时（例如网络中断留下的
  半开连接），那个请求要等到读取超时才放行；Redis 正常重启、连接被服务端关闭时，phpredis 能察觉并自动重连
  （实测关掉后照常可用）。它影响这台服务器上所有用 phpredis 持久连接的代码，扩展包不替你改。
- **Redis 带密码时**：扩展包把密码交给 phpredis 在新建连接时认证（`context.auth`），默认设置下正常请求仍是 2 次往返
  （phpredis 把存活检查的 `ECHO` 与认证合在一次往返里发）。但关掉 `echo_check_liveness` 之后仍是 **2 次**，
  比不带密码时多 1 次：phpredis 从持久连接池取连接时会重新认证一次，扩展包绕不开（2026-11-07 实测，phpredis 6.3）。

### 本地用 `php artisan serve` 时

`php artisan serve` 会在项目有 `.env` 时清掉子进程里除少数几个（`APP_ENV`、`PATH` 等）以外的环境变量，让子进程
自己重读 `.env`。所以在命令行里 `export FAIL2BAN_ENABLED=true` 之类**不会生效**：把 `FAIL2BAN_*` 写进 `.env`，
或者用 `php artisan serve --no-reload`（不清环境变量）。

## 宿主接入

扩展包与宿主之间有四个接入点（照 Horizon 的 `Horizon::auth()`，在宿主自己的服务提供者 `boot()` 里登记），
都不登记时用扩展包的默认行为。

### 1. 豁免

返回 `true` 的访客不会被自动或手动封禁（命中规则照常记录，达到出现次数时写一条「已豁免」事件并发出 `BanSkipped`）。
`$ip` 是规范化之后的单个地址（`::ffff:1.2.3.4` 已换成 `1.2.3.4`）；从命令行手动封禁时 `$request` 为 null。
它只在命中规则、达到出现次数，或 IPv6 网段被封的访客来访时才被调用，不在正常请求的路径上。

```php
use Illuminate\Http\Request;
use Maximus\Fail2Ban\Fail2Ban;

Fail2Ban::exemptUsing(fn (string $ip, ?Request $request) => in_array($ip, MerchantServer::ips(), true));
```

### 2. 拒绝响应外形

替换被封访客看到的内容；状态码、`Cache-Control: no-store`、`X-Robots-Tag: noindex` 仍由扩展包强制。
`$payload` 有 `status`、`message`、`ip`、`incident`、`recorded_at`（显示开关关掉的项为 null），以及 `format`：
按扩展包的默认规则这次会给页面（`'html'`，Accept 明确列出 `text/html`）还是 JSON（`'json'`）。
要让浏览器仍看到页面，在 `format` 为 `html` 时渲染自带的视图 `fail2ban::blocked`。返回值可以是路由能返回的任何东西。

```php
Fail2Ban::respondUsing(fn (Request $request, array $payload) => $payload['format'] === 'html'
    ? view('fail2ban::blocked', [
        'status' => $payload['status'], 'message' => $payload['message'],
        'ip' => $payload['ip'], 'incident' => $payload['incident'], 'recordedAt' => $payload['recorded_at'],
    ])
    : ['code' => $payload['status'], 'message' => $payload['message'], 'data' => (object) array_filter([
        'ip' => $payload['ip'], 'incident' => $payload['incident'], 'recorded_at' => $payload['recorded_at'],
    ])]);
```

### 3. 操作人

面板与命令行的操作日志里记谁做的。不登记时取已登录用户的标识，取不到时命令行记 `console`、面板记 `unknown`。

```php
Fail2Ban::actorUsing(fn (?Request $request) => $request?->user()?->name);
```

### 4. 面板授权与中间件

面板（`/fail2ban` 与 `/fail2ban/api/*`）依次经过：扩展包自己的异常渲染、`fail2ban.panel.middleware`（默认 `['web']`，
宿主在这里接入自己的登录中间件）、授权 `viewFail2Ban`。授权默认只允许本地环境，生产环境要宿主自己定义：

```php
// config/fail2ban.php
'panel' => ['middleware' => ['web', 'auth'], /* … */],

// AppServiceProvider::boot()
Gate::define('viewFail2Ban', fn ($user = null) => $user?->is_admin === true);
```

- 面板接口要求登录中间件对未登录的请求返回 **401**：抛 `Illuminate\Auth\AuthenticationException`
  （Laravel 自带的 `auth` 中间件就是这样）即可，扩展包会渲染成 401；中间件自己返回响应的，请让它对面板接口返回 401。
- **宿主的异常处理把一切渲染成「HTTP 200 加业务码」时**，宿主不用为面板改任何东西：面板接口（`{path}/api/*`）里的
  **所有**异常都由扩展包渲染成带真实状态码的 JSON——校验失败 422、未登录 401、无权限 403、不存在 404、令牌失效 419、
  其它 HttpException 按它自己的状态码、服务器错误 500（`message` 跟随 `app.debug`：开着时是异常消息并附调用栈，
  关着时是 `Server Error`）。**上报仍交给宿主**：宿主的日志与告警照常收到面板接口里的异常。
  仍由宿主渲染的只有：面板以外的路由，以及面板外壳页面（`{path}` 本身，未登录时怎么跳转由宿主决定）。
- 只在某个域名下提供面板：`FAIL2BAN_PANEL_DOMAIN=ops.example.com`（`fail2ban.panel.domain`，照 Horizon 的 `domain`），默认不限定。

### 封禁事件

扩展包只在封禁、解封这些时刻发出事件，**不发任何通知**：要不要告警、发到哪里、怎么记，由宿主监听事件自己处理。
三个事件都在 `Maximus\Fail2Ban\Events` 下，都在改动写进 Redis 之后才发出；派发包在 `rescue()` 里，
监听器抛异常只经宿主的异常处理上报，不会让封禁或解封报成失败。载荷是普通数组与字符串，可以交给队列监听器。

| 事件 | 何时发出 | 载荷 |
| --- | --- | --- |
| `IpBanned` | 一次封禁真的生效：自动封禁（访客已被封时不发），或在面板、用 `fail2ban:ban` 手动封禁（以这次为准覆盖已有封禁，每次都发） | `ban`：封禁记录（`source` 为 `auto` / `manual`；另有 `visitor`、`incident`、`rule`、`ip`、`region`、`observe`、`banned_at`、`unban_at`、`ban_minutes`，手动时有 `operator`、`note`，形状见 `Contracts\BanRepository`）；`incident`：写进历史的攻击事件；`via`：手动封禁的来源 `panel` / `console`，自动封禁为 `null` |
| `IpUnbanned` | 一个封禁被提前解除，每个封禁一次；解封时访客其实没有被封则不发 | `visitor`：访客键；`ban`：被解除的封禁记录；`actor`：操作人；`via`：`panel` / `console`；`reason`：见下 |
| `BanSkipped` | 访客达到封禁规则的出现次数，但被宿主豁免（`Fail2Ban::exemptUsing()`），没有封；同一规则同一时间范围内一次 | `incident`：处置为 `exempted` 的攻击事件 |

`IpUnbanned::$reason` 的取值（类常量）：

- `manual`（`REASON_MANUAL`）：在面板或用 `fail2ban:unban` 解封；
- `allowlisted`（`REASON_ALLOWLISTED`）：加入白名单时连带解除落在条目里的封禁；
- `observation_cleared`（`REASON_OBSERVATION_CLEARED`）：运行模式切到拦截时解除观察期间产生的自动封禁。

**封禁到期没有事件**：到期就是 Redis 键自然过期，没有进程在跑，扩展包无从得知。需要「到期」时，可以在收到
`IpBanned` 时按 `$event->ban['unban_at']` 自己排一个延迟任务。手动封禁覆盖已有封禁时，被覆盖的那次也不发 `IpUnbanned`。

宿主监听的最小例子（Laravel 11+ 按监听器 `handle()` 的参数类型自动发现；也可以在服务提供者的 `boot()` 里
`Event::listen(IpBanned::class, NotifyOps::class)`）：

```php
namespace App\Listeners;

use Illuminate\Contracts\Queue\ShouldQueue;
use Maximus\Fail2Ban\Events\IpBanned;
use Maximus\Fail2Ban\Events\IpUnbanned;

class NotifyOps implements ShouldQueue
{
    public function handle(IpBanned|IpUnbanned $event): void
    {
        if ($event instanceof IpBanned && $event->ban['source'] === 'auto' && ! $event->ban['observe']) {
            // 自动封禁：发告警
        }

        if ($event instanceof IpUnbanned && $event->reason === IpUnbanned::REASON_MANUAL) {
            // 有人手动解封：记一笔
        }
    }
}
```

## 扩展规则库

不改扩展包代码，在 `config/fail2ban.php` 里就能做三件事。什么都不配时，行为与内置的五条规则完全一样。配置改完如果用了 `php artisan config:cache`，记得重新缓存。

### 追加清单条目

敏感文件探测、已知漏洞探测、扫描器特征三份内置清单在 `lists.{规则标识}.extra` 里追加。写法与 `resources/rules/*.txt` 相同：只有首尾的 `*` 是通配符，不分大小写；已知漏洞探测里以 `?` 开头的条目匹配查询串。

```php
'lists' => [
    'sensitive-path' => ['extra' => ['/internal-backup/*', '*.tfstate']],
    'known-exploit'  => ['extra' => ['*/old-gateway/notify.php']],   // 默认一次即封，只写正常访客绝不会请求的地址
    'scanner-agent'  => ['extra' => ['EvilCrawler']],                // 浏览器标识里按词查找的字面量
],
```

### 排除清单条目（处理误伤）

某个内置条目误伤了正常访客，把它的原文写进 `except`（不分大小写），它就不再命中。排除是按条目算的：`/.env` 同时符合 `*/.env*` 与 `*.env` 两条，只排除其中一条它仍会命中。

```php
'lists' => [
    'sensitive-path' => ['except' => ['*.do', '*.action']],
],
```

`lists` 里写了不认识的规则标识会直接报错，免得以为排除生效了其实没有。

### 登记自定义规则

写一个实现 `Maximus\Fail2Ban\Contracts\Rule` 的类，在 `rules` 里用它的标识登记，加上 `class` 和四项默认设置。类由容器解析，构造函数可以注入依赖。它会和内置规则一样出现在面板的规则表里、能改动作与三个数值、参与检测与统计。新规则建议先用 `observe` 跑几天，确认不误伤再改成 `ban`。

```php
'rules' => [
    // ……内置的五条保持不变……
    'legacy-api' => [
        'class' => \App\Fail2Ban\LegacyApiPath::class,
        'action' => 'observe', 'window' => 30, 'count' => 3, 'ban' => 240,
    ],
],
```

```php
namespace App\Fail2Ban;

use Illuminate\Http\Request;
use Maximus\Fail2Ban\Contracts\Rule;
use Symfony\Component\HttpFoundation\Response;

class LegacyApiPath implements Rule
{
    public function id(): string { return 'legacy-api'; }            // 必须等于登记用的键
    public function name(): string { return '旧版接口探测'; }
    public function description(): string { return '请求已下线的 /api/v0/ 接口（404）时记一次，同一路径只算一次。'; }
    public function isPathRule(): bool { return true; }              // 地址类规则排在 404 扫描之前，只记一条
    public function countMode(): string { return self::COUNT_DISTINCT; } // 或 COUNT_EACH：每次请求都算
    public function key(Request $request): ?string { return $request->getPathInfo(); } // COUNT_EACH 时返回 null

    public function matches(Request $request, Response $response): bool
    {
        // 每个请求都会调用：先做最便宜的判断，正常请求要在几微秒内返回 false
        return $response->getStatusCode() === 404 && str_starts_with($request->getPathInfo(), '/api/v0/');
    }
}
```

在内置规则的标识下写 `class`，就用你的子类替换那条内置规则（标识要相同）。类不存在、没实现 `Rule`、`id()` 与键对不上时会抛 `InvalidArgumentException`。

### 扩展的代价

不配 `lists` 时，三份内置清单直接取预先编译好的 `resources/rules/compiled.php`（opcache 共享内存），
不读文本、不编正则。某份清单配了 `extra` 或 `except`，这份清单就要在**每个请求**里读文本清单、合并配置、
编正则（php-fpm 每个请求结束都会清空进程内的缓存）。2026-11-07 在 PHP 8.4、opcache 开启、模拟 php-fpm
请求边界的条件下实测，规则检测每个请求的中位数：

| 改了哪份清单 | 受影响的请求 | 不改 | 改了 |
| --- | --- | --- | --- |
| 都不改 | — | 正常请求 7 微秒，带查询串 10 微秒，404 18 微秒 | — |
| `scanner-agent` | 所有带浏览器标识的请求 | 7–10 微秒 | 约 36–40 微秒 |
| `known-exploit` | 带查询串的请求、404 | 10–18 微秒 | 约 37–45 微秒 |
| `sensitive-path` | 404 | 18 微秒 | 约 127 微秒 |

这些都发生在响应发出之后，不让访客多等，但会多占一会儿 php-fpm 进程。登记自定义规则本身没有这项代价，
代价取决于你的 `matches()` 写得多快。测法见下面「开发」一节的基准。

## 开发

```bash
composer install
vendor/bin/phpunit                    # 默认配置，不跑 benchmark 分组
vendor/bin/phpunit --group benchmark  # 只跑依赖计时的测试（每请求基准、中间件基准、Redis 故障耗时、病态输入耗时上限）
```

benchmark 分组的断言是耗时上限，机器忙时可能偶发失败，所以默认不跑；改了规则检测、中间件或连接相关的代码后单独跑一遍。
只跑其中一个文件时也要带 `--group benchmark`（例如 `vendor/bin/phpunit --group benchmark --filter RulesPerRequestBenchmarkTest`），
否则会被默认配置排除。

改了 `resources/rules/*.txt` 之后重新生成编译产物，并把两者一起提交（测试 `CompiledListsTest` 会检查两者一致）：

```bash
composer compile-rules            # 即 php bin/compile-rules；加 --check 只检查不写入
```

规则检测的「每请求」基准（模拟 php-fpm：每次测量前清空本包所有进程内缓存，opcache 开启）：

```bash
php -d opcache.enable_cli=1 tests/Support/rules-benchmark.php [--customized[=sensitive-path,known-exploit,scanner-agent]]
```

测试连接真实 Redis（phpredis）：主机取环境变量 `FAIL2BAN_TEST_REDIS_HOST`（默认 `127.0.0.1`），
端口 `FAIL2BAN_TEST_REDIS_PORT`（默认 6379）。每个测试开始前都会 `FLUSHDB` 这个实例的 **0 号库**（只动 0 号库），
请只指向测试专用实例，**不要指向存有数据的 Redis**。测试串行执行，靠这一步互相隔离。

最省事的做法是起一个一次性的 Redis，再跑测试：

```bash
docker run -d --rm --name fail2ban-test-redis -p 6379:6379 redis:7-alpine
vendor/bin/phpunit
# Redis 不在本机或端口不同：FAIL2BAN_TEST_REDIS_HOST=… FAIL2BAN_TEST_REDIS_PORT=… vendor/bin/phpunit
```

带密码时的往返测试另需一个带密码的实例：`FAIL2BAN_TEST_REDIS_AUTH_HOST`、`FAIL2BAN_TEST_REDIS_AUTH_PORT`（默认 6379）、
`FAIL2BAN_TEST_REDIS_AUTH_PASSWORD`；没有设置时这条测试跳过。

## 许可证

MIT，见 [LICENSE](LICENSE)。
