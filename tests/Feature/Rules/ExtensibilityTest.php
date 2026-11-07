<?php

namespace Maximus\Fail2Ban\Tests\Feature\Rules;

use InvalidArgumentException;
use Maximus\Fail2Ban\Contracts\Rule;
use Maximus\Fail2Ban\Contracts\SettingsRepository;
use Maximus\Fail2Ban\Inspector;
use Maximus\Fail2Ban\RuleHit;
use Maximus\Fail2Ban\Rules\KnownExploit;
use Maximus\Fail2Ban\Rules\ScannerAgent;
use Maximus\Fail2Ban\Rules\SensitivePath;
use Maximus\Fail2Ban\Rules\Support\CompiledLists;
use Maximus\Fail2Ban\Rules\Support\PatternList;
use Maximus\Fail2Ban\Tests\Feature\Rules\Fixtures\LegacyApiPath;
use Maximus\Fail2Ban\Tests\Feature\Rules\Fixtures\PortalLoginFailure;
use Maximus\Fail2Ban\Tests\Feature\Rules\Fixtures\WrongId;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use ReflectionMethod;

/**
 * 宿主不改扩展包代码，就能追加、排除清单条目、登记自定义规则；什么都不配时与内置五条完全一致。
 */
class ExtensibilityTest extends RuleTestCase
{
    /**
     * 按给定配置重新从容器解析 Inspector（和中间件、面板后端拿到的是同一个绑定）。
     */
    private function inspector(array $config = []): Inspector
    {
        foreach ($config as $key => $value) {
            config(["fail2ban.$key" => $value]);
        }

        $this->app->forgetInstance(Inspector::class);

        return $this->app->make(Inspector::class);
    }

    private function ids(Inspector $inspector, string $uri, int $status = 404, array $headers = [], array $actions = self::ALL_ON): array
    {
        return array_map(
            fn (RuleHit $hit) => $hit->rule,
            $inspector->inspect($this->makeRequest('GET', $uri, $headers), $this->response($status), $actions),
        );
    }

    // ---------------------------------------------------------------- 什么都不配

    #[Test]
    public function the_container_binding_is_a_singleton_built_from_config(): void
    {
        $this->assertSame($this->app->make(Inspector::class), $this->app->make(Inspector::class));
        $this->assertSame(
            Inspector::BUILTIN,
            array_map(get_class(...), app(Inspector::class)->rules()),
        );
    }

    /**
     * 一批固定样例：三份清单里每个条目各造一个地址，加上正常请求、查询串利用、各种标识。
     */
    public static function fixedSamples(): array
    {
        $samples = [];

        foreach (glob(dirname(__DIR__, 3).'/resources/rules/*-paths.txt') as $file) {
            foreach (PatternList::parse($file) as $entry) {
                $core = trim($entry, '*');
                $uri = $entry[0] === '?'
                    ? '/index.php?a=1&'.ltrim(trim(substr($entry, 1), '*'), '?').'x'
                    : (str_starts_with($entry, '*') ? '/p' : '').(str_starts_with($core, '/') || str_starts_with($entry, '*') ? '' : '/').$core.(str_ends_with($entry, '*') ? 'z' : '');
                $samples[$entry] = [$uri];
            }
        }

        foreach ([
            '/v1/transactions/pay', '/v1/prepay/abc?sign=x%2By&notify_url=https%3A%2F%2Fa.b%2Fc', '/merchant/deposit-orders?page=2',
            '/random-404', '/x?q=%3Cscript%3E', '/x?f=..%2f..%2fetc%2fpasswd', '/?x=${jndi:ldap://a/b}', '/storage/images/a.png',
        ] as $uri) {
            $samples[$uri] = [$uri];
        }

        return $samples;
    }

    #[Test]
    #[DataProvider('fixedSamples')]
    public function with_nothing_configured_hits_equal_the_builtin_five(string $uri): void
    {
        $configured = app(Inspector::class);
        $builtin = new Inspector(array_map(fn (string $class) => new $class, Inspector::BUILTIN));

        foreach ([404, 200] as $status) {
            foreach (['GuzzleHttp/7', 'sqlmap/1.7', 'Nuclei'] as $agent) {
                $request = $this->makeRequest('GET', $uri, ['User-Agent' => $agent]);
                $this->assertEquals(
                    array_map(fn (RuleHit $hit) => [$hit->rule, $hit->key, $hit->path], $builtin->inspect($request, $this->response($status), self::ALL_ON)),
                    array_map(fn (RuleHit $hit) => [$hit->rule, $hit->key, $hit->path], $configured->inspect($request, $this->response($status), self::ALL_ON)),
                    "$status $uri $agent",
                );
            }
        }
    }

    #[Test]
    public function empty_lists_config_changes_nothing(): void
    {
        $inspector = $this->inspector(['lists' => [
            'sensitive-path' => ['extra' => [], 'except' => []],
            'known-exploit' => [],
        ]]);

        // 只写了空数组的追加与排除等于没配：仍然用编译产物
        $compiled = fn (string $id) => (new ReflectionMethod($inspector->rule($id), 'compiled'))->invoke($inspector->rule($id));
        $this->assertSame(CompiledLists::for(SensitivePath::class), $compiled('sensitive-path'));
        $this->assertSame(CompiledLists::for(KnownExploit::class), $compiled('known-exploit'));
    }

    // ---------------------------------------------------------------- 追加

    #[Test]
    public function extra_entries_match(): void
    {
        $inspector = $this->inspector(['lists' => [
            'sensitive-path' => ['extra' => ['/internal-backup/*', '*.tfstate']],
            'known-exploit' => ['extra' => ['*/old-gateway/notify.php', '?*debug_token=*']],
            'scanner-agent' => ['extra' => ['EvilCrawler']],
        ]]);

        $this->assertSame(['sensitive-path'], $this->ids($inspector, '/internal-backup/readme'));
        $this->assertSame(['sensitive-path'], $this->ids($inspector, '/terraform.tfstate'));
        $this->assertSame(['known-exploit'], $this->ids($inspector, '/old-gateway/notify.php'));
        $this->assertSame(['known-exploit'], $this->ids($inspector, '/v1/prepay/abc?debug_token=1', 200));
        $this->assertSame(['scanner-agent'], $this->ids($inspector, '/', 200, ['User-Agent' => 'Mozilla/5.0 EvilCrawler/1.0']));

        // 不配时这些都不命中（或只算 404 扫描）
        $plain = new Inspector(array_map(fn (string $class) => new $class, Inspector::BUILTIN));
        $this->assertSame(['not-found-scan'], $this->ids($plain, '/internal-backup/readme'));
        $this->assertSame([], $this->ids($plain, '/v1/prepay/abc?debug_token=1', 200));
        $this->assertSame([], $this->ids($plain, '/', 200, ['User-Agent' => 'Mozilla/5.0 EvilCrawler/1.0']));
    }

    #[Test]
    public function extra_path_entries_count_only_on_unsuccessful_responses_unless_marked_any_status(): void
    {
        $inspector = $this->inspector(['lists' => [
            'sensitive-path' => ['extra' => ['/internal-backup/*'], 'extra_any_status' => ['*.tfstate', '/ops-secret']],
            'known-exploit' => ['extra' => ['*/old-gateway/notify'], 'extra_any_status' => ['*/old-gateway/debug']],
            'scanner-agent' => ['extra_any_status' => ['EvilCrawler']],
        ]]);

        // extra：默认归「响应不是成功才算」（宿主可能真有的页面，更保守）
        $this->assertSame([], $this->ids($inspector, '/internal-backup/readme', 200));
        $this->assertSame(['sensitive-path'], $this->ids($inspector, '/internal-backup/readme', 403));
        $this->assertSame([], $this->ids($inspector, '/old-gateway/notify', 200));
        $this->assertSame(['known-exploit'], $this->ids($inspector, '/old-gateway/notify', 500));

        // extra_any_status：不看状态码
        $this->assertSame(['sensitive-path'], $this->ids($inspector, '/terraform.tfstate', 200));
        $this->assertSame(['sensitive-path'], $this->ids($inspector, '/ops-secret', 200), '不带点的条目也要过预筛');
        $this->assertSame(['sensitive-path'], $this->ids($inspector, '/ops-secret/', 302));
        $this->assertSame(['known-exploit'], $this->ids($inspector, '/old-gateway/debug', 200));

        // 扫描器特征本来就不看状态码，两种写法一样
        $this->assertSame(['scanner-agent'], $this->ids($inspector, '/', 200, ['User-Agent' => 'Mozilla/5.0 EvilCrawler/1.0']));

        // 内置条目不受影响
        $this->assertSame(['sensitive-path'], $this->ids($inspector, '/.env', 200));
        $this->assertSame([], $this->ids($inspector, '/horizon', 200));
        $this->assertSame(['sensitive-path'], $this->ids($inspector, '/horizon', 401));
    }

    #[Test]
    public function only_extra_any_status_configured_still_compiles_at_runtime(): void
    {
        $inspector = $this->inspector(['lists' => ['sensitive-path' => ['extra_any_status' => ['/ops-secret']]]]);
        $compiled = (new ReflectionMethod($inspector->rule('sensitive-path'), 'compiled'))->invoke($inspector->rule('sensitive-path'));

        $this->assertNotSame(CompiledLists::for(SensitivePath::class), $compiled);
    }

    // ---------------------------------------------------------------- 排除

    #[Test]
    public function excepted_entries_no_longer_match(): void
    {
        $inspector = $this->inspector(['lists' => [
            'sensitive-path' => ['except' => ['*.PHP', '*/.env*']],
            'known-exploit' => ['except' => ['*/_ignition/execute-solution*', '?*allow_url_include=*']],
            'scanner-agent' => ['except' => ['nikto']],
        ]]);

        // 敏感文件探测：排除后按 404 扫描算（大小写不敏感）
        $this->assertSame(['not-found-scan'], $this->ids($inspector, '/shell.php'));
        $this->assertSame(['not-found-scan'], $this->ids($inspector, '/.env.local'));
        $this->assertSame(['sensitive-path'], $this->ids($inspector, '/.env'), '排除按条目算：/.env 还符合没被排除的 *.env');
        $this->assertSame(['sensitive-path'], $this->ids($inspector, '/.git/config'), '没排除的照常命中');

        // 已知漏洞探测：排除后落到下一条地址类规则
        $this->assertSame(['sensitive-path'], $this->ids($inspector, '/_ignition/execute-solution'));
        $this->assertNotContains('known-exploit', $this->ids($inspector, '/?-d+allow_url_include%3d1', 200));
        $this->assertContains('known-exploit', $this->ids($inspector, '/?-d+auto_prepend_file%3dphp://input', 200), '没排除的照常命中');

        // 两类都排除：不看状态码的 *.php 与非成功才算的面板
        $this->assertSame([], $this->ids($inspector, '/shell.php', 200));
        $inspector2 = $this->inspector(['lists' => ['sensitive-path' => ['except' => ['/horizon/*'], 'extra_any_status' => ['/mine-any'], 'extra' => ['/mine']]]]);
        $this->assertSame(['not-found-scan'], $this->ids($inspector2, '/horizon', 404));
        $this->assertSame([], $this->ids($inspector2, '/horizon', 403));
        $inspector3 = $this->inspector(['lists' => ['sensitive-path' => ['extra_any_status' => ['/mine-any'], 'extra' => ['/mine'], 'except' => ['/MINE-ANY', '/mine']]]]);
        $this->assertSame([], $this->ids($inspector3, '/mine-any', 200), '排除对追加的条目同样生效');
        $this->assertSame(['not-found-scan'], $this->ids($inspector3, '/mine', 404));

        // 扫描器特征
        $this->assertSame([], $this->ids($inspector, '/', 200, ['User-Agent' => 'Mozilla/5.00 (Nikto/2.1.6)']));
        $this->assertSame(['scanner-agent'], $this->ids($inspector, '/', 200, ['User-Agent' => 'sqlmap/1.7']));
    }

    #[Test]
    public function a_list_rule_built_by_hand_takes_extra_and_except(): void
    {
        $rule = new ScannerAgent(extra: ['EvilCrawler'], except: ['sqlmap']);

        $this->assertTrue($rule->matches($this->makeRequest('GET', '/', ['User-Agent' => 'EvilCrawler']), $this->response(200)));
        $this->assertFalse($rule->matches($this->makeRequest('GET', '/', ['User-Agent' => 'sqlmap/1.7']), $this->response(200)));
        $this->assertTrue((new ScannerAgent)->matches($this->makeRequest('GET', '/', ['User-Agent' => 'sqlmap/1.7']), $this->response(200)), '别的实例不受影响');
    }

    // ---------------------------------------------------------------- 自定义规则

    private function withCustomRules(): Inspector
    {
        return $this->inspector(['rules' => config('fail2ban.rules') + [
            'login-failure' => ['class' => PortalLoginFailure::class, 'action' => 'observe', 'window' => 10, 'count' => 5, 'ban' => 60],
            'legacy-api' => ['class' => LegacyApiPath::class, 'action' => 'ban', 'window' => 30, 'count' => 3, 'ban' => 240],
        ]]);
    }

    #[Test]
    public function custom_rules_are_registered_in_order(): void
    {
        $inspector = $this->withCustomRules();

        // 自定义地址类规则排在 404 扫描（兜底）之前，其它自定义规则排在最后。
        $this->assertSame(
            ['known-exploit', 'sensitive-path', 'legacy-api', 'not-found-scan', 'scanner-agent', 'attack-pattern', 'login-failure'],
            array_keys($inspector->rules()),
        );
        $this->assertInstanceOf(PortalLoginFailure::class, $inspector->rule('login-failure'));
        $this->assertSame(Rule::COUNT_EACH, $inspector->rule('login-failure')->countMode());
        $this->assertSame(Rule::COUNT_DISTINCT, $inspector->rule('legacy-api')->countMode());
    }

    #[Test]
    public function custom_rules_take_part_in_inspection(): void
    {
        $inspector = $this->withCustomRules();
        $actions = self::ALL_ON + ['login-failure' => 'observe', 'legacy-api' => 'ban'];

        // 非地址类：与其它规则各记各的
        $hits = $inspector->inspect($this->makeRequest('POST', '/portal/api/login'), $this->response(401), $actions);
        $this->assertSame(['login-failure'], array_map(fn (RuleHit $hit) => $hit->rule, $hits));
        $this->assertNull($hits[0]->key);

        // 地址类：排在 404 扫描前面，命中后 404 扫描不再记
        $this->assertSame(['legacy-api'], $this->ids($inspector, '/api/v0/orders', 404, [], $actions));
        $this->assertSame(['not-found-scan'], $this->ids($inspector, '/api/v1/orders', 404, [], $actions));

        // 动作为 off 或动作表里没有时不检测，和内置规则一样
        $this->assertSame(['not-found-scan'], $this->ids($inspector, '/api/v0/orders', 404, [], ['legacy-api' => 'off'] + $actions));
        $this->assertSame(['not-found-scan'], $this->ids($inspector, '/api/v0/orders', 404, [], self::ALL_ON));
    }

    #[Test]
    public function custom_rules_get_settings_defaults(): void
    {
        $this->withCustomRules();
        $settings = app(SettingsRepository::class);

        $defaults = $settings->defaults();
        $this->assertSame(['action' => 'observe', 'window' => 10, 'count' => 5, 'ban' => 60], $defaults['rules']['login-failure']);
        $this->assertSame(['action' => 'ban', 'window' => 30, 'count' => 3, 'ban' => 240], $defaults['rules']['legacy-api']);
        $this->assertArrayNotHasKey('class', $defaults['rules']['login-failure'], '类名不是可保存的设置项');

        // 保存与校验连真实 Redis，见 CustomRuleSettingsTest
        // 面板保存过的值盖在默认值上（resolve 是 lookup() 读 Redis 后用的那一步）
        $resolved = $settings->resolve(['rules.login-failure.action' => 'ban', 'rules.login-failure.count' => '7']);
        $this->assertSame(['action' => 'ban', 'window' => 10, 'count' => 7, 'ban' => 60], $resolved['rules']['login-failure']);
    }

    #[Test]
    public function a_builtin_rule_can_be_replaced_by_a_subclass(): void
    {
        $inspector = $this->inspector(['rules' => array_replace_recursive(config('fail2ban.rules'), [
            'sensitive-path' => ['class' => StricterSensitivePath::class],
        ])]);

        $this->assertInstanceOf(StricterSensitivePath::class, $inspector->rule('sensitive-path'));
        $this->assertSame(['known-exploit', 'sensitive-path', 'not-found-scan', 'scanner-agent', 'attack-pattern'], array_keys($inspector->rules()));
        $this->assertSame(['sensitive-path'], $this->ids($inspector, '/secret.txt'));
    }

    // ---------------------------------------------------------------- 配置写错要报错

    public static function badConfigs(): array
    {
        return [
            '清单的规则标识写错' => [['lists' => ['sensitive-paths' => ['except' => ['*.php']]]]],
            '给没有清单的规则配清单' => [['lists' => ['attack-pattern' => ['extra' => ['x']]]]],
            '自定义规则没写类' => [['rules' => ['mystery' => ['action' => 'ban', 'window' => 1, 'count' => 1, 'ban' => 1]]]],
            '类不存在' => [['rules' => ['mystery' => ['class' => 'App\\Nope', 'action' => 'ban']]]],
            '类没实现 Rule' => [['rules' => ['mystery' => ['class' => \stdClass::class, 'action' => 'ban']]]],
            '标识对不上' => [['rules' => ['legacy-api' => ['class' => WrongId::class, 'action' => 'ban']]]],
        ];
    }

    #[Test]
    #[DataProvider('badConfigs')]
    public function misconfiguration_is_reported(array $config): void
    {
        if (isset($config['rules'])) {
            $config['rules'] = config('fail2ban.rules') + $config['rules'];
        }

        $this->expectException(InvalidArgumentException::class);

        $this->inspector($config);
    }

    // ---------------------------------------------------------------- 只在第一次用到时构建一次

    #[Test]
    public function lists_are_built_lazily_and_once(): void
    {
        // 解析绑定时不读清单、不编正则：带一个非法条目也能解析出来，第一次检测才报错。
        // （「任意状态」组每个请求都要看，所以第一次检测任何请求都会构建清单。）
        $inspector = $this->inspector(['lists' => ['sensitive-path' => ['extra' => ['/bad*entry']]]]);

        try {
            $this->ids($inspector, '/v1/transactions/pay', 200);
            $this->fail('非法条目应在第一次匹配时报错');
        } catch (InvalidArgumentException) {
        }

        // 同一个规则对象上的清单只建一次；同样的配置建出同样的清单；不配时用编译产物
        $rule = new SensitivePath(extra: ['/x/*']);
        $compiled = new ReflectionMethod($rule, 'compiled');
        $this->assertSame($compiled->invoke($rule), $compiled->invoke($rule));
        $this->assertSame($compiled->invoke($rule), $compiled->invoke(new SensitivePath(extra: ['/x/*'])));
        $this->assertNotSame($compiled->invoke($rule), $compiled->invoke(new SensitivePath));
        $this->assertSame(CompiledLists::for(SensitivePath::class), $compiled->invoke(new SensitivePath));
    }

    #[Test]
    public function builtin_count_modes_agree_with_their_keys(): void
    {
        $expected = [
            'known-exploit' => Rule::COUNT_DISTINCT,
            'sensitive-path' => Rule::COUNT_DISTINCT,
            'not-found-scan' => Rule::COUNT_DISTINCT,
            'scanner-agent' => Rule::COUNT_EACH,
            'attack-pattern' => Rule::COUNT_DISTINCT,
        ];

        $request = $this->makeRequest('GET', '/.env?x=%3Cscript%3E', ['User-Agent' => 'sqlmap/1.7']);

        foreach (app(Inspector::class)->rules() as $id => $rule) {
            $this->assertSame($expected[$id], $rule->countMode(), $id);
            $this->assertSame($rule->countMode() === Rule::COUNT_EACH, $rule->key($request) === null, $id);
        }
    }
}

/**
 * 测试用：替换内置敏感文件探测的子类，额外把 /secret.txt 算进来。
 */
class StricterSensitivePath extends SensitivePath
{
    public function matches(\Illuminate\Http\Request $request, \Symfony\Component\HttpFoundation\Response $response): bool
    {
        return parent::matches($request, $response)
            || ($response->getStatusCode() === 404 && $request->getPathInfo() === '/secret.txt');
    }
}
