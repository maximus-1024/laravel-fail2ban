<?php

namespace Maximus\Fail2Ban\Tests\Feature\Rules;

use Maximus\Fail2Ban\Rules\NotFoundScan;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

class NotFoundScanTest extends RuleTestCase
{
    public static function notFoundPaths(): array
    {
        return [
            '接口地址拼错' => ['POST', '/v1/transactions/pays'],
            '收银台订单号错' => ['GET', '/v1/prepay'],
            '浏览器自动请求' => ['GET', '/favicon.ico'],
            '随便一个目录' => ['GET', '/backup/'],
            '带查询参数' => ['GET', '/v2/transactions/pay?out_trade_no=1'],
        ];
    }

    #[Test]
    #[DataProvider('notFoundPaths')]
    public function any_404_matches(string $method, string $uri): void
    {
        $this->assertTrue((new NotFoundScan)->matches($this->makeRequest($method, $uri), $this->response(404)));
    }

    public static function otherStatuses(): array
    {
        return [[200], [201], [204], [301], [302], [400], [401], [403], [405], [419], [422], [429], [500], [502], [503]];
    }

    #[Test]
    #[DataProvider('otherStatuses')]
    public function other_statuses_do_not_match(int $status): void
    {
        $this->assertFalse((new NotFoundScan)->matches(
            $this->makeRequest('GET', '/v1/transactions/pays'),
            $this->response($status),
        ));
    }

    #[Test]
    public function key_is_the_path_without_query(): void
    {
        $rule = new NotFoundScan;

        $a = $rule->key($this->makeRequest('GET', '/wp-content/x?ver=1'));
        $b = $rule->key($this->makeRequest('GET', '/wp-content/x?ver=2&y=3'));
        $c = $rule->key($this->makeRequest('GET', '/wp-content/x'));

        $this->assertSame('/wp-content/x', $a);
        $this->assertSame($a, $b);
        $this->assertSame($a, $c);
        $this->assertNotSame($a, $rule->key($this->makeRequest('GET', '/wp-content/y')));
    }

    #[Test]
    public function very_long_paths_use_a_digest_key(): void
    {
        $path = '/'.str_repeat('a', 5000);
        $key = (new NotFoundScan)->key($this->makeRequest('GET', $path.'?x=1'));

        $this->assertSame('sha1:'.sha1($path), $key);
    }
}
