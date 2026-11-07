<?php

namespace Maximus\Fail2Ban\Tests\Feature\Rules;

use Illuminate\Support\Carbon;
use InvalidArgumentException;
use Maximus\Fail2Ban\Contracts\Rule;
use Maximus\Fail2Ban\Inspector;
use Maximus\Fail2Ban\RuleHit;
use Maximus\Fail2Ban\Rules\NotFoundScan;
use Maximus\Fail2Ban\Rules\Support\PatternList;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

class InspectorTest extends RuleTestCase
{
    protected function tearDown(): void
    {
        Carbon::setTestNow();

        parent::tearDown();
    }

    #[Test]
    public function default_rules_are_the_five_in_r27_order(): void
    {
        $rules = app(Inspector::class)->rules();

        $this->assertSame(['known-exploit', 'sensitive-path', 'not-found-scan', 'scanner-agent', 'attack-pattern'], array_keys($rules));
        $this->assertSame([true, true, true, false, false], array_values(array_map(fn (Rule $rule) => $rule->isPathRule(), $rules)));

        $names = array_map(fn (Rule $rule) => $rule->name(), $rules);
        $this->assertSame(['已知漏洞探测', '敏感文件探测', '404 扫描', '扫描器特征', '攻击特征'], array_values($names));

        foreach ($rules as $id => $rule) {
            $this->assertSame($id, $rule->id());
            $this->assertNotSame('', $rule->description());
        }

        $this->assertEqualsCanonicalizing(array_keys(config('fail2ban.rules')), array_keys($rules));
        $this->assertInstanceOf(NotFoundScan::class, app(Inspector::class)->rule('not-found-scan'));
        $this->assertNull(app(Inspector::class)->rule('nope'));
    }

    public static function overlappingPathRequests(): array
    {
        return [
            // 路径同时在利用清单、敏感清单里，且是 404
            'Ignition 利用地址' => ['/_ignition/execute-solution', 'known-exploit'],
            'PHPUnit 利用地址（也是 .php）' => ['/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php', 'known-exploit'],
            // QNAP 不是 PHP 生态，归在敏感文件探测；这里用 PHP-CGI 的利用地址，
            // 它同时符合敏感文件探测的 cgi-bin。
            'QNAP 利用地址（归在敏感文件探测）' => ['/cgi-bin/nas_sharing.cgi', 'sensitive-path'],
            'PHP-CGI 利用地址（也是 cgi-bin）' => ['/cgi-bin/php5', 'known-exploit'],
            '.env（也是 404）' => ['/.env', 'sensitive-path'],
            '.git（也是 404）' => ['/.git/config', 'sensitive-path'],
            '普通 404' => ['/v1/transactions/pays', 'not-found-scan'],
        ];
    }

    #[Test]
    #[DataProvider('overlappingPathRequests')]
    public function only_the_first_path_rule_is_recorded(string $path, string $expected): void
    {
        $this->assertSame([$expected], $this->hitIds($this->makeRequest('GET', $path), $this->response(404)));
    }

    #[Test]
    public function jndi_on_a_404_keeps_404_scan_out(): void
    {
        $request = $this->makeRequest('GET', '/nothing-here', ['User-Agent' => '${jndi:ldap://x.y/a}']);

        $this->assertSame(['known-exploit'], $this->hitIds($request, $this->response(404)));
        $this->assertSame(['known-exploit'], $this->hitIds($request, $this->response(200)));
    }

    #[Test]
    public function a_disabled_earlier_path_rule_lets_the_next_one_count(): void
    {
        $request = $this->makeRequest('GET', '/_ignition/execute-solution');
        $response = $this->response(404);

        $this->assertSame(['sensitive-path'], $this->hitIds($request, $response, ['known-exploit' => 'off'] + self::ALL_ON));
        $this->assertSame(['not-found-scan'], $this->hitIds($request, $response, ['known-exploit' => 'off', 'sensitive-path' => 'off'] + self::ALL_ON));
        $this->assertSame(['known-exploit'], $this->hitIds($request, $response, ['sensitive-path' => 'off'] + self::ALL_ON));
    }

    #[Test]
    public function request_rules_are_recorded_alongside_a_path_rule(): void
    {
        $request = $this->makeRequest('GET', '/.env?id=1%27%20or%20%271%27=%271', ['User-Agent' => 'sqlmap/1.7.2#stable (https://sqlmap.org)']);

        $this->assertSame(['sensitive-path', 'scanner-agent', 'attack-pattern'], $this->hitIds($request, $this->response(404)));
        // .env 不看状态码
        $this->assertSame(['sensitive-path', 'scanner-agent', 'attack-pattern'], $this->hitIds($request, $this->response(200)));

        // 运维面板只在响应不是成功时算
        $request = $this->makeRequest('GET', '/horizon?id=1%27%20or%20%271%27=%271', ['User-Agent' => 'sqlmap/1.7.2#stable (https://sqlmap.org)']);
        $this->assertSame(['sensitive-path', 'scanner-agent', 'attack-pattern'], $this->hitIds($request, $this->response(403)));
        $this->assertSame(['scanner-agent', 'attack-pattern'], $this->hitIds($request, $this->response(200)));
    }

    #[Test]
    public function off_rules_are_not_inspected(): void
    {
        $request = $this->makeRequest('GET', '/_ignition/execute-solution?x=%3Cscript%3E', ['User-Agent' => 'nikto ${jndi:ldap://x.y/a}']);
        $response = $this->response(404);

        $this->assertSame(['known-exploit', 'scanner-agent', 'attack-pattern'], $this->hitIds($request, $response));
        $this->assertSame([], $this->hitIds($request, $response, array_fill_keys(array_keys(self::ALL_ON), 'off')));
        $this->assertSame([], $this->hitIds($request, $response, []), '动作表里没有的规则按关闭处理');
        $this->assertSame([], $this->hitIds($request, $response, array_fill_keys(array_keys(self::ALL_ON), 'BAN')), '拼错的动作按关闭处理');
        $this->assertSame(['known-exploit', 'attack-pattern'], $this->hitIds($request, $response, ['scanner-agent' => 'off'] + self::ALL_ON));
        $this->assertSame(['scanner-agent'], $this->hitIds($request, $response, ['scanner-agent' => 'ban']));
    }

    #[Test]
    public function observe_is_inspected_like_ban(): void
    {
        $request = $this->makeRequest('GET', '/.env', ['User-Agent' => 'sqlmap/1.7']);

        $this->assertSame(
            ['sensitive-path', 'scanner-agent'],
            $this->hitIds($request, $this->response(404), array_fill_keys(array_keys(self::ALL_ON), 'observe')),
        );
    }

    #[Test]
    public function hits_carry_rule_key_and_a_truncated_record(): void
    {
        Carbon::setTestNow('2026-11-07 14:02:11');
        config(['fail2ban.path_max' => 20]);

        // token 是凭据参数，记录前打码，所以记录里是 token=***。
        $uri = '/.env?token=abcdefghijklmnopqrstuvwxyz';
        $hits = app(Inspector::class)->inspect(
            $this->makeRequest('get', $uri, ['User-Agent' => 'sqlmap/1.7']),
            $this->response(404),
            self::ALL_ON,
        );

        $this->assertCount(2, $hits);
        $this->assertContainsOnlyInstancesOf(RuleHit::class, $hits);

        [$path, $agent] = $hits;

        $this->assertSame('sensitive-path', $path->rule);
        $this->assertSame('/.env', $path->key);
        $this->assertSame('GET', $path->method);
        $this->assertSame('/.env?token=***', $path->path);
        $this->assertSame(['time' => Carbon::now()->getTimestamp(), 'method' => 'GET', 'path' => '/.env?token=***'], $path->record());

        $this->assertSame('scanner-agent', $agent->rule);
        $this->assertNull($agent->key);
    }

    #[Test]
    public function record_uses_the_real_method_and_scrubs_invalid_utf8(): void
    {
        $request = $this->makeRequest('POST', "/x\xff\xfe.php?_method=DELETE", ['X-HTTP-Method-Override' => 'PUT']);
        $hits = app(Inspector::class)->inspect($request, $this->response(404), self::ALL_ON);

        $this->assertSame('POST', $hits[0]->method);
        $this->assertTrue(mb_check_encoding($hits[0]->path, 'UTF-8'));
        $this->assertTrue(mb_check_encoding($hits[0]->key, 'UTF-8'));
        $this->assertNotFalse(json_encode($hits[0]->record()));
    }

    #[Test]
    public function dedup_keys_follow_each_rules_rule(): void
    {
        $inspector = app(Inspector::class);
        $keys = function (string $uri, int $status, string $agent = 'GuzzleHttp/7') use ($inspector): array {
            $hits = $inspector->inspect($this->makeRequest('GET', $uri, ['User-Agent' => $agent]), $this->response($status), self::ALL_ON);

            return array_column($hits, 'key', 'rule');
        };

        // 404 扫描与敏感文件探测：换查询参数，键不变。
        $this->assertSame($keys('/nope?a=1', 404)['not-found-scan'], $keys('/nope?a=2', 404)['not-found-scan']);
        $this->assertSame($keys('/.env?a=1', 404)['sensitive-path'], $keys('/.env?b=2', 404)['sensitive-path']);
        $this->assertSame($keys('/.env', 404)['sensitive-path'], $keys('/.env?b=2', 404)['sensitive-path']);

        // 攻击特征：完全相同的地址键相同，换查询参数键不同。
        $this->assertSame($keys('/x?q=%3Cscript%3E', 200)['attack-pattern'], $keys('/x?q=%3Cscript%3E', 200)['attack-pattern']);
        $this->assertNotSame($keys('/x?q=%3Cscript%3E', 200)['attack-pattern'], $keys('/x?q=%3Cscript%3E&r=1', 200)['attack-pattern']);

        // 扫描器特征：每次请求都算。
        $this->assertArrayHasKey('scanner-agent', $keys('/', 200, 'nikto'));
        $this->assertNull($keys('/', 200, 'nikto')['scanner-agent']);
    }

    #[Test]
    public function duplicate_rule_ids_are_rejected(): void
    {
        $this->expectException(InvalidArgumentException::class);

        new Inspector([new NotFoundScan, new NotFoundScan]);
    }

    #[Test]
    public function custom_rule_sets_are_supported(): void
    {
        $inspector = new Inspector([new NotFoundScan]);

        $this->assertSame(['not-found-scan'], array_keys($inspector->rules()));
        $this->assertCount(1, $inspector->inspect($this->makeRequest('GET', '/.env'), $this->response(404), self::ALL_ON));
    }

    #[Test]
    public function bundled_lists_parse_and_compile(): void
    {
        foreach (glob(dirname(__DIR__, 3).'/resources/rules/*.txt') as $file) {
            $this->assertNotEmpty(PatternList::parse($file), $file);
        }

        // 编译不报错（含非法条目时会抛异常）
        $this->hitIds($this->makeRequest('GET', '/x', ['User-Agent' => 'x']), $this->response(404));
        $this->assertSame(PREG_NO_ERROR, preg_last_error());
    }

    #[Test]
    public function list_entries_with_inner_wildcards_are_rejected(): void
    {
        $this->expectException(InvalidArgumentException::class);

        PatternList::regex(['/a*b']);
    }

    #[Test]
    public function list_wildcards_mean_exact_prefix_suffix_and_contains(): void
    {
        $regex = PatternList::regex(['/exact', '/prefix*', '*.suffix', '*middle*']);
        $matches = fn (string $subject) => PatternList::test($regex, [$subject]);

        $this->assertTrue($matches('/exact'));
        $this->assertFalse($matches('/exact/x'));
        $this->assertTrue($matches('/prefix/x'));
        $this->assertFalse($matches('/x/prefix'));
        $this->assertTrue($matches('/x.suffix'));
        $this->assertFalse($matches('/x.suffix/y'));
        $this->assertFalse($matches("/x.suffix\n"));
        $this->assertTrue($matches('/a/middle/b'));
        $this->assertFalse($matches('/nothing'));
        $this->assertFalse(PatternList::test(PatternList::regex([]), ['/x']));
    }
}
