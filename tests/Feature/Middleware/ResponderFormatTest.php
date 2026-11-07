<?php

namespace Maximus\Fail2Ban\Tests\Feature\Middleware;

use Illuminate\Http\Request;
use Maximus\Fail2Ban\Fail2Ban;
use PHPUnit\Framework\Attributes\Test;

/**
 * 交给宿主拒绝响应外形回调的载荷里有 format，说明这次请求按包的默认规则
 * 会给页面（html）还是 JSON（json），宿主可以据此给浏览器一个页面。
 */
class ResponderFormatTest extends MiddlewareTestCase
{
    #[Test]
    public function the_payload_says_whether_the_default_would_be_a_page_or_json(): void
    {
        $this->setMode('block');
        $this->api('/_ignition/execute-solution')->assertNotFound();

        $formats = [];
        Fail2Ban::respondUsing(function (Request $request, array $payload) use (&$formats) {
            $formats[] = $payload['format'];

            return $payload['format'] === 'html'
                ? response(view('fail2ban::blocked', [
                    'status' => $payload['status'], 'message' => $payload['message'], 'ip' => $payload['ip'],
                    'incident' => $payload['incident'], 'recordedAt' => $payload['recorded_at'],
                ]))
                : ['code' => $payload['status'], 'message' => $payload['message']];
        });

        $this->api('/ok')->assertForbidden()->assertJson(['code' => 403]);
        $this->visit('/ok', ['Accept' => 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'])
            ->assertForbidden()
            ->assertSee('<html', false);
        $this->visit('/ok', ['Accept' => 'application/json'])->assertForbidden();

        $this->assertSame(['json', 'html', 'json'], $formats);
    }
}
