<?php

namespace Maximus\Fail2Ban\Tests\Feature\Middleware;

use Carbon\CarbonImmutable;
use Illuminate\Http\Request;
use Maximus\Fail2Ban\Fail2Ban;
use PHPUnit\Framework\Attributes\Test;

/**
 * 拒绝响应。
 */
class BlockedResponseTest extends MiddlewareTestCase
{
    private const MESSAGE = '检测到来自你的地址的异常访问，相关行为已被记录，请立即停止。如属误判，请把事件编号发给客服。';

    private array $ban;

    protected function setUp(): void
    {
        parent::setUp();

        $this->setMode('block');
        $this->api('/_ignition/execute-solution')->assertNotFound();
        $this->ban = $this->ban();
    }

    private function recordedAt(): string
    {
        return CarbonImmutable::createFromTimestamp($this->ban['banned_at'], 'Asia/Shanghai')->format('Y-m-d H:i:s');
    }

    #[Test]
    public function api_clients_get_json_with_message_ip_incident_and_time(): void
    {
        foreach ([['Accept' => '*/*'], ['Accept' => 'application/json'], ['Accept' => '']] as $headers) {
            $response = $this->visit('/ok', $headers);

            $response->assertForbidden();
            $this->assertStringStartsWith('application/json', $response->headers->get('Content-Type'));
            $this->assertSame([
                'code' => 403,
                'message' => self::MESSAGE,
                'data' => [
                    'ip' => self::IP,
                    'incident' => $this->ban['incident'],
                    'recorded_at' => $this->recordedAt(),
                ],
            ], $response->json());
            $this->assertStringContainsString('no-store', $response->headers->get('Cache-Control'));
            $this->assertSame('noindex', $response->headers->get('X-Robots-Tag'));
            $this->assertNoUnbanTime($response);
        }

        $this->assertSame(0, static::$controllerRuns);
    }

    #[Test]
    public function browsers_get_the_page(): void
    {
        // Symfony 测试请求默认的 Accept 就是浏览器的 text/html,...
        $response = $this->visit('/ok');

        $response->assertForbidden();
        $this->assertStringStartsWith('text/html', $response->headers->get('Content-Type'));
        $response->assertSee(self::MESSAGE);
        $response->assertSee($this->ban['incident']);
        $response->assertSee(self::IP);
        $response->assertSee($this->recordedAt());
        $this->assertStringContainsString('no-store', $response->headers->get('Cache-Control'));
        $this->assertSame('noindex', $response->headers->get('X-Robots-Tag'));
        $this->assertNoUnbanTime($response);
    }

    #[Test]
    public function every_request_of_a_banned_visitor_gets_the_same_configured_status(): void
    {
        $this->settings()->save(['response' => ['status' => 429, 'message' => '请停止扫描。']], 'test');

        foreach (['/ok', '/nope', '/boom', '/.env', '/items/1'] as $uri) {
            foreach (['GET', 'POST', 'PUT', 'DELETE'] as $method) {
                $response = $this->api($uri, [], self::IP, $method);
                $response->assertStatus(429);
                $this->assertSame('请停止扫描。', $response->json('message'));
                $this->assertSame(429, $response->json('code'));
                $this->assertSame($this->ban['incident'], $response->json('data.incident'));
            }
        }

        $this->assertSame(0, static::$controllerRuns);
    }

    #[Test]
    public function the_three_display_switches_remove_their_items(): void
    {
        $this->settings()->save(['response' => ['show_ip' => false, 'show_time' => false]], 'test');

        $json = $this->api('/ok')->assertForbidden()->json();
        $this->assertSame(['incident' => $this->ban['incident']], $json['data']);

        $page = $this->visit('/ok')->assertForbidden();
        $page->assertSee($this->ban['incident']);
        $page->assertDontSee(self::IP);
        $page->assertDontSee($this->recordedAt());

        $this->settings()->save(['response' => ['show_incident' => false]], 'test');

        $response = $this->api('/ok')->assertForbidden();
        $this->assertSame('{"code":403,"message":"'.self::MESSAGE.'","data":{}}', $response->getContent());
        $this->visit('/ok')->assertDontSee($this->ban['incident']);
    }

    #[Test]
    public function the_host_can_replace_the_shape_but_not_the_status(): void
    {
        $received = null;

        Fail2Ban::respondUsing(function (Request $request, array $payload) use (&$received) {
            $received = $payload;

            return response()->json([
                'code' => 1001,
                'message' => $payload['message'],
                'data' => ['incident' => $payload['incident']],
                'request_id' => 'req-1',
            ], 200);
        });

        $response = $this->api('/ok');

        $response->assertForbidden();
        $this->assertSame('req-1', $response->json('request_id'));
        $this->assertSame([
            'status' => 403,
            'message' => self::MESSAGE,
            'ip' => self::IP,
            'incident' => $this->ban['incident'],
            'recorded_at' => $this->recordedAt(),
            'format' => 'json',
        ], $received);
        $this->assertStringContainsString('no-store', $response->headers->get('Cache-Control'));
        $this->assertSame(0, static::$controllerRuns);

        // 闭包可以返回任何路由能返回的东西；关掉的项传 null
        $this->settings()->save(['response' => ['show_ip' => false]], 'test');
        Fail2Ban::respondUsing(fn (Request $request, array $payload) => $payload);

        $response = $this->api('/ok')->assertForbidden();
        $this->assertNull($response->json('ip'));
        $this->assertSame($this->ban['incident'], $response->json('incident'));
    }

    private function assertNoUnbanTime($response): void
    {
        $this->assertFalse($response->headers->has('Retry-After'));

        $unbanAt = CarbonImmutable::createFromTimestamp($this->ban['unban_at'], 'Asia/Shanghai');

        foreach ([$unbanAt->format('Y-m-d H:i'), $unbanAt->format('H:i:s'), (string) $this->ban['unban_at'], 'unban', '解封'] as $needle) {
            $this->assertStringNotContainsString($needle, $response->getContent());
        }
    }
}
