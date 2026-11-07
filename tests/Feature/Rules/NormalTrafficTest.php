<?php

namespace Maximus\Fail2Ban\Tests\Feature\Rules;

use Illuminate\Http\JsonResponse;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

/**
 * 没有命中任何规则的请求，不产生任何命中。
 *
 * 样例模拟一个收款类 JSON 接口的常见流量：带签名的授权头、长数字订单号、回调地址、钱包地址、中文备注。所有值都是虚构的。
 */
class NormalTrafficTest extends RuleTestCase
{
    private const AUTHORIZATION = 'DEMO-SHA256-RSA2048 mchid="1024",appid="71073031-615b-4d58-a92e-b7469089d4fa",nonce="bb516e65-265e-4e5b-88c3-bab2cec79213",timestamp="1700000000",sign="osaULzwzws3Czoo+1KRXA5MSy1cv4wLTEdtFTCsFiJiqSG5LeAAyw6jjSjv+69gmydG0uHPdpdioV2TcsZbtEw6A7OtzlNECmW3TPMmIdZ6tYA/dn+ZufquQpiN4eNirEO0sTDOEbPw5pRTD4NXLkl6AzQkiiWWEmWlLRVhbPMqO/K1BeQpsfxkDmddNGTuPV7tUNWMUVwFOrWEpH3ErQ1ctosgT+PhbNZbGcSBW+afjCYoJ3wjk+xCcAaBsDYQRhZiyyRQrPOhcwgjzeFENve41TixGrUq2QrkMIhhEvlHs+XOwv/oHDa5fpnl9D0JKuU5RUAg0JFpcNm1HgDfs8o=="';

    private const PAY_BODY = '{"out_trade_no":"900000000000000001","amount":12000,"chain":"TRON","currency":"USDT","notify_url":"https://shop.example.com/notify/in/29","return_url":"https://shop.example.com/back/in/29","locale":"zh"}';

    private const PAYOUT_BODY = '{"out_trade_no":"900000000000000002","amount":100,"chain":"ETH","currency":"USDT","notify_url":"https://shop.example.com/notify","to_address":"0xeb6CD206dCaFCFC39AC09aFDD1dFf8DD10B06A4D"}';

    /**
     * 商户服务器用的各种通用库，加上空标识与不带标识。
     */
    public static function clientAgents(): array
    {
        return [
            'curl' => ['curl/8.5.0'],
            'Guzzle' => ['GuzzleHttp/7 curl/8.5.0 PHP/8.3.1'],
            'okhttp' => ['okhttp/4.12.0'],
            'python-requests' => ['python-requests/2.31.0'],
            'Go' => ['Go-http-client/2.0'],
            'Java' => ['Java/17.0.2'],
            'axios' => ['axios/1.6.2'],
            'node-fetch' => ['node-fetch/1.0 (+https://github.com/bitinn/node-fetch)'],
            '空标识' => [''],
            '不带标识' => [null],
        ];
    }

    #[Test]
    #[DataProvider('clientAgents')]
    public function merchant_api_calls_from_generic_clients_are_clean(?string $agent): void
    {
        $headers = ['User-Agent' => $agent, 'Authorization' => self::AUTHORIZATION, 'Content-Type' => 'application/json'];

        $calls = [
            ['POST', '/v1/transactions/pay', self::PAY_BODY, $this->hostJson(0, 'ok')],
            ['POST', '/v1/transactions/pay/', self::PAY_BODY, $this->hostJson(0, 'ok')],
            ['POST', '/v1/transactions/payout', self::PAYOUT_BODY, $this->hostJson(0, 'ok')],
            // 业务层「订单不存在」：HTTP 200，业务 code 404
            ['POST', '/v1/transactions/pay/query', '{"out_trade_no":"900000000000000001"}', $this->hostJson(404, '订单不存在')],
            ['POST', '/v1/transactions/payout/query', '{"out_trade_no":"900000000000000002"}', $this->hostJson(404, '订单不存在')],
            // 验签失败、参数错误、限流
            ['POST', '/v1/transactions/pay', self::PAY_BODY, $this->hostJson(401, '签名错误', 401)],
            ['POST', '/v1/transactions/pay', self::PAY_BODY, $this->hostJson(422, 'amount 必须是整数', 422)],
            ['POST', '/v1/transactions/pay', self::PAY_BODY, $this->hostJson(429, '请求太频繁', 429)],
            // 系统错误
            ['POST', '/v1/transactions/pay', self::PAY_BODY, $this->hostJson(500, '系统错误', 500)],
            ['POST', '/v1/transactions/payout', self::PAYOUT_BODY, new JsonResponse(['message' => 'Server Error'], 500)],
            ['POST', '/v1/transactions/payout', self::PAYOUT_BODY, new JsonResponse(['message' => 'Bad Gateway'], 502)],
            ['POST', '/v1/transactions/payout', self::PAYOUT_BODY, new JsonResponse(['message' => 'Service Unavailable'], 503)],
        ];

        foreach ($calls as [$method, $uri, $body, $response]) {
            $this->assertSame([], $this->hitIds($this->makeRequest($method, $uri, $headers, $body), $response), "$method $uri {$response->getStatusCode()}");
        }
    }

    public static function cashierAndBackOffice(): array
    {
        $prepay = '4442ed3ed642f7308babe09b9007675ed487e0309a82d';
        $browser = 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1';
        $chrome = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36';

        return [
            // 收银台
            '收银台取订单' => ['GET', "/v1/prepay/$prepay", $browser, 200, ''],
            '收银台取订单带语言' => ['GET', "/v1/prepay/$prepay?locale=zh&t=1700000000", $browser, 200, ''],
            '收银台切换公链 PUT' => ['PUT', "/v1/prepay/$prepay", $browser, 200, '{"chain":"BSC","currency":"USDT"}'],
            '收银台订单已过期' => ['GET', "/v1/prepay/$prepay", $browser, 410, ''],
            '收银台跨域预检' => ['OPTIONS', "/v1/prepay/$prepay", $browser, 204, ''],
            // 商户后台
            '登录' => ['POST', '/merchant/auth/login', $chrome, 200, '{"identifier":"merchant@example.com","password":"p@ss\' or 1=1","captcha_key":"abc"}'],
            '验证码' => ['GET', '/merchant/common/captcha', $chrome, 200, ''],
            '代收订单列表' => ['GET', '/merchant/deposit-orders?page=1&per_page=20&chain=TRON&token_id=1&status=1&start_date=2026-11-01&end_date=2026-11-07&merchant_order_no=900000000000000001&to_address=TXYZabc123&application_id=01909762-9246-7c29-85a5-795d0', $chrome, 200, ''],
            '代收订单按描述查' => ['GET', '/merchant/deposit-orders?description=%E6%B5%8B%E8%AF%95%E8%AE%A2%E5%8D%95+select+union+script', $chrome, 200, ''],
            '代收订单导出' => ['GET', '/merchant/deposit-orders/export?is_download=1&start_date=2026-11-01&end_date=2026-11-07', $chrome, 200, ''],
            '代收订单详情' => ['GET', '/merchant/deposit-orders/12345', $chrome, 200, ''],
            '代收订单补发通知' => ['POST', '/merchant/deposit-orders/12345/notify', $chrome, 200, ''],
            '代收订单删除 DELETE' => ['DELETE', '/merchant/deposit-orders/12345', $chrome, 200, ''],
            '提现订单取消 PATCH' => ['PATCH', '/merchant/merchant-withdrawal-orders/77/cancel', $chrome, 200, ''],
            '改密码 PUT' => ['PUT', '/merchant/merchants/reset-password', $chrome, 200, '{"password":"x"}'],
            '应用更新 PUT' => ['PUT', '/merchant/applications/71073031-615b-4d58-a92e-b7469089d4fa', $chrome, 200, ''],
            '应用删除 DELETE' => ['DELETE', '/merchant/applications/71073031-615b-4d58-a92e-b7469089d4fa', $chrome, 200, ''],
            '提现钱包开关 PATCH' => ['PATCH', '/merchant/merchant-withdrawal-wallets/3/toggle-enable', $chrome, 200, ''],
            '提现规则删除 DELETE' => ['DELETE', '/merchant/merchant-withdrawal-rules/3', $chrome, 200, ''],
            '平台公钥' => ['GET', '/merchant/applications/plat-public-key', $chrome, 200, ''],
            '导入模板' => ['GET', '/merchant/common/downloads/withdrawals/import-template', $chrome, 200, ''],
            '批量导入记录' => ['GET', '/merchant/withdrawal-import-batch/9/records?page=1', $chrome, 200, ''],
            '余额变动' => ['GET', '/merchant/balance-changes?page=1&type=deposit', $chrome, 200, ''],
            '代理佣金导出' => ['GET', '/agent/commissions/export?start_date=2026-10-01&end_date=2026-10-31', $chrome, 200, ''],
            '二次验证' => ['GET', '/merchant/google2fa/enable', $chrome, 200, ''],
            '未登录' => ['GET', '/merchant/merchants/me', $chrome, 401, ''],
            '无权限' => ['DELETE', '/merchant/deposit-orders/12345', $chrome, 403, ''],
            '会话过期' => ['POST', '/merchant/deposit-orders', $chrome, 419, ''],
            // 运营后台
            '运营后台订单搜索' => ['GET', '/portal/api/deposit-orders?keyword=TXYZ%20%E6%B5%8B%E8%AF%95&range=custom&custom_range=2026-11-01+~+2026-11-07&status=1&page=2', $chrome, 200, ''],
            '运营后台订单详情页' => ['GET', '/portal/deposit-orders/-5/detail', $chrome, 200, ''],
            '运营后台补单预览' => ['POST', '/portal/api/deposit-orders/12/transactions/reconcile-preview', $chrome, 200, ''],
            '运营后台统计' => ['GET', '/portal/api/statistics?range=month', $chrome, 200, ''],
            // 根地址与系统错误
            '根地址' => ['GET', '/', 'curl/8.5.0', 200, ''],
            '后台系统错误' => ['GET', '/merchant/dashboard/dw-stats', $chrome, 500, ''],
        ];
    }

    #[Test]
    #[DataProvider('cashierAndBackOffice')]
    public function cashier_and_back_office_traffic_is_clean(string $method, string $uri, string $agent, int $status, string $body): void
    {
        $request = $this->makeRequest($method, $uri, [
            'User-Agent' => $agent,
            'Referer' => 'https://merchant.example.com/deposit-orders?page=2',
            'Content-Type' => 'application/json',
        ], $body);

        $this->assertSame([], $this->hitIds($request, $this->response($status)));
    }

    public static function urlAndSignatureParameters(): array
    {
        return [
            '回调地址原样' => ['/v1/prepay/abc?notify_url=https://shop.example.com/notify/in/29&return_url=https://shop.example.com/back/in/29'],
            '回调地址编码' => ['/v1/prepay/abc?notify_url=https%3A%2F%2Fshop.example.com%2Fnotify&return_url=https%3A%2F%2Fshop.example.com%2Fpay%2Fresult.php%3Forder%3D900000000000000001%26status%3Dsuccess'],
            '回调地址带端口与路径参数' => ['/v1/prepay/abc?notify_url=http%3A%2F%2F203.0.113.5%3A8080%2Fapi%2Fv1%2Fcallback%2Fdemo-app%3Bversion%3D2'],
            '收银台链接' => ['/v1/prepay/abc?payment_url=%2Fpay%2Forder%3Fprepay_id%3D4442ed3ed642f7308babe'],
            '签名、时间戳、随机串' => ['/v1/prepay/abc?mchid=1024&appid=71073031-615b-4d58-a92e-b7469089d4fa&nonce=bb516e65-265e-4e5b-88c3-bab2cec79213&timestamp=1700000000&sign=osaULzwzws3Czoo%2B1KRXA5MSy1cv4wLTEdtFTCsFiJiqSG5L%2FK1BeQpsfxkDmddNGTuPV7tUNWMUVwFOrWEpH3ErQ1ctosgT%2BPhbNZbGcSBW%2BafjCYoJ3wjk%3D%3D'],
            'base64 原样' => ['/v1/prepay/abc?data=eyJvdXRfdHJhZGVfbm8iOiI5MDAwMDAwMDAwMDAwMDAwMDEifQ==&sig=a+b/c=='],
            '中文' => ['/v1/prepay/abc?subject=%E5%85%85%E5%80%BC%E8%AE%A2%E5%8D%95%EF%BC%9A%E4%BC%9A%E5%91%98%E5%B9%B4%E8%B4%B9&remark=测试（退款）'],
            '普通英文单词' => ['/v1/prepay/abc?subject=Please+select+a+plan&remark=union+members+script+writer+sleep+well&note=drop+table+tennis+or+1+more'],
            '金额与小数' => ['/v1/prepay/abc?amount=12000&pay_amount=6.10&fee=0.01&expire_second=1800'],
            '时间' => ['/v1/prepay/abc?expired_at=2026-11-02T08%3A30%3A00%2B00%3A00&create_time=1748250779'],
            '钱包地址与哈希' => ['/v1/prepay/abc?to_address=Trb7RydVJiLF5LTk6ifrSGbEAPiNYBHaEM&hash=0x9f2c0e1d5b3a7c4e8f6a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e'],
            // 2026-11-07：与新加的查询串利用特征、PHP 注入特征字面相近的正常写法
            '中文以 %AD 字节开头的编码' => ['/merchant/deposit-orders?description=%E6%AD%A3%E5%B8%B8%E8%AE%A2%E5%8D%95'],
            '描述里有 env 与减号' => ['/merchant/deposit-orders?description=test--env+prod&remark=-d+option'],
            '动作参数' => ['/merchant/deposit-orders/export?action=download&is_download=1'],
            '订单号像序列化' => ['/portal/api/deposit-orders?keyword=O:20&range=custom'],
            '美元金额' => ['/v1/prepay/abc?description=%24_10+off&amount=10'],
        ];
    }

    #[Test]
    #[DataProvider('urlAndSignatureParameters')]
    public function url_signature_and_text_parameters_are_clean(string $uri): void
    {
        foreach ([200, 500] as $status) {
            $this->assertSame([], $this->hitIds($this->makeRequest('GET', $uri), $this->response($status)), "$uri $status");
        }
    }
}
