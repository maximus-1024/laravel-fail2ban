<?php

namespace Maximus\Fail2Ban\Tests\Feature\Rules;

use Maximus\Fail2Ban\Inspector;
use Maximus\Fail2Ban\RuleHit;
use Maximus\Fail2Ban\Rules\AttackPattern;
use Maximus\Fail2Ban\Rules\Support\Redactor;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

/**
 * 展示用的地址在记录前给凭据参数打码；攻击特征的去重键只存完整地址的摘要。
 */
class RedactionTest extends RuleTestCase
{
    public static function credentialParameters(): array
    {
        return [
            '签名' => ['/x?sign=xQ7mLd%2B4K%3D%3D&mchid=1024', '/x?sign=***&mchid=1024'],
            'signature 大写' => ['/x?Signature=abc&a=1', '/x?Signature=***&a=1'],
            'token' => ['/x?token=abc', '/x?token=***'],
            'access_token' => ['/x?a=1&access_token=eyJhbGciOi', '/x?a=1&access_token=***'],
            'key' => ['/x?KEY=k1', '/x?KEY=***'],
            'api_key 连字符' => ['/x?api-key=k1', '/x?api-key=***'],
            'apikey' => ['/x?apikey=k1', '/x?apikey=***'],
            'secret' => ['/x?secret=s', '/x?secret=***'],
            'client_secret' => ['/x?client_secret=s', '/x?client_secret=***'],
            'password' => ['/x?password=p%40ss', '/x?password=***'],
            'passwd' => ['/x?passwd=p', '/x?passwd=***'],
            'pwd' => ['/x?PWD=p', '/x?PWD=***'],
            'auth' => ['/x?auth=Basic+abc', '/x?auth=***'],
            'authorization' => ['/x?Authorization=Bearer%20abc', '/x?Authorization=***'],
            '以 _secret 结尾' => ['/x?merchant_secret=s', '/x?merchant_secret=***'],
            '以 _key 结尾' => ['/x?x_api_key=s&captcha_key=c', '/x?x_api_key=***&captcha_key=***'],
            '以 _token 结尾' => ['/x?refresh_token=r', '/x?refresh_token=***'],
            '参数名编码' => ['/x?%73ign=abc', '/x?%73ign=***'],
            '数组参数' => ['/x?user[password]=p&user[name]=n', '/x?user[password]=***&user[name]=n'],
            '数组参数编码' => ['/x?user%5Bpassword%5D=p', '/x?user%5Bpassword%5D=***'],
            '攻击载荷照样打码' => ['/x?token=%27%20or%201=1&id=1%27%20or%201=1', '/x?token=***&id=1%27%20or%201=1'],
        ];
    }

    #[Test]
    #[DataProvider('credentialParameters')]
    public function credential_values_are_masked(string $uri, string $expected): void
    {
        $this->assertSame($expected, Redactor::uri($uri));
    }

    public static function ordinaryParameters(): array
    {
        return [
            ['/x'], ['/x?'], ['/x?a=1&b=2'], ['/x?token_id=1&chain=TRON'], ['/x?nonce=abc&timestamp=1700000000&mchid=1024&appid=7107'],
            ['/x?token'], ['/x?token='], ['/x?keyword=abc&monkey=1'], ['/x?signed_at=1&design=a'], ['/.env'],
            ['/v1/prepay/abc?notify_url=https%3A%2F%2Fa.b%2Fc%3Ftoken%3Dabc'],
        ];
    }

    #[Test]
    #[DataProvider('ordinaryParameters')]
    public function other_parameters_are_left_alone(string $uri): void
    {
        $this->assertSame($uri, Redactor::uri($uri));
    }

    #[Test]
    public function hit_records_are_masked_before_truncation(): void
    {
        config(['fail2ban.path_max' => 30]);

        $uri = '/.env?sign='.str_repeat('A', 200).'&x=1';
        $hits = app(Inspector::class)->inspect($this->makeRequest('GET', $uri), $this->response(404), self::ALL_ON);

        $this->assertSame('sensitive-path', $hits[0]->rule);
        $this->assertSame('/.env?sign=***&x=1', $hits[0]->path);
        $this->assertStringNotContainsString('AAAA', json_encode([$hits[0]->key, $hits[0]->record()]));
    }

    #[Test]
    public function every_rule_records_a_masked_uri(): void
    {
        $request = $this->makeRequest('GET', '/.env?id=1%27%20or%20%271%27%3D%271&token=secret-value', ['User-Agent' => 'sqlmap/1.7']);
        $hits = app(Inspector::class)->inspect($request, $this->response(404), self::ALL_ON);

        $this->assertSame(['sensitive-path', 'scanner-agent', 'attack-pattern'], array_map(fn (RuleHit $hit) => $hit->rule, $hits));

        foreach ($hits as $hit) {
            $this->assertSame('/.env?id=1%27%20or%20%271%27%3D%271&token=***', $hit->path, $hit->rule);
            $this->assertStringNotContainsString('secret-value', json_encode([$hit->key, $hit->record()]), $hit->rule);
        }
    }

    #[Test]
    public function attack_pattern_keys_are_digests_of_the_full_uri(): void
    {
        $rule = new AttackPattern;
        $uri = '/x?q=%3Cscript%3E&sign=secret-value';
        $key = $rule->key($this->makeRequest('GET', $uri));

        $this->assertSame('sha1:'.sha1($uri), $key);
        $this->assertStringNotContainsString('secret', $key);
        $this->assertStringNotContainsString('script', $key);

        // 口径不变：完全相同的地址同一个键，换查询参数换键
        $this->assertSame($key, $rule->key($this->makeRequest('GET', $uri)));
        $this->assertNotSame($key, $rule->key($this->makeRequest('GET', $uri.'&n=1')));
    }
}
