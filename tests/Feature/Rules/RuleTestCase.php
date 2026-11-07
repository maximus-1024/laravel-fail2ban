<?php

namespace Maximus\Fail2Ban\Tests\Feature\Rules;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Maximus\Fail2Ban\Inspector;
use Maximus\Fail2Ban\Fail2BanServiceProvider;
use Maximus\Fail2Ban\RuleHit;
use Orchestra\Testbench\TestCase;
use Symfony\Component\HttpFoundation\Response;

/**
 * 规则测试的公共工具：按原样的请求行造请求（不经 Request::create 的重新编码）。
 *
 * 规则是纯逻辑，不连 Redis，所以不继承 Tests\TestCase（它在每个测试前清空测试 Redis）。
 */
abstract class RuleTestCase extends TestCase
{
    protected function getPackageProviders($app): array
    {
        return [Fail2BanServiceProvider::class];
    }

    /**
     * 五条规则都开着（动作为 ban）。
     */
    protected const ALL_ON = [
        'not-found-scan' => 'ban',
        'sensitive-path' => 'ban',
        'scanner-agent' => 'ban',
        'attack-pattern' => 'ban',
        'known-exploit' => 'ban',
    ];

    /**
     * 造一个请求。$uri 是原样的请求目标（照抄进 REQUEST_URI），$headers 是请求头。
     *
     * @param  array<string, string|null>  $headers  值为 null 表示不带这个请求头
     */
    protected function makeRequest(string $method, string $uri, array $headers = [], string $body = ''): Request
    {
        $at = strpos($uri, '?');
        $query = $at === false ? '' : substr($uri, $at + 1);

        $server = [
            'REQUEST_METHOD' => $method,
            'REQUEST_URI' => $uri,
            'QUERY_STRING' => $query,
            'HTTP_HOST' => 'api.example.com',
            'SERVER_NAME' => 'api.example.com',
            'SERVER_PORT' => 443,
            'HTTPS' => 'on',
            'SCRIPT_NAME' => '/index.php',
            'SCRIPT_FILENAME' => '/var/www/app/public/index.php',
            'REMOTE_ADDR' => '203.0.113.47',
        ];

        $headers += ['User-Agent' => 'GuzzleHttp/7'];

        foreach ($headers as $name => $value) {
            if ($value !== null) {
                $key = strtoupper(str_replace('-', '_', $name));
                $server[in_array($key, ['CONTENT_TYPE', 'CONTENT_LENGTH'], true) ? $key : 'HTTP_'.$key] = $value;
            }
        }

        // 规则只看原样的请求行，不用解析好的参数，这里也就不解析（避免 max_input_vars 限制）。
        return new Request([], [], [], [], [], $server, $body);
    }

    protected function response(int $status = 200, string $content = ''): Response
    {
        return new Response($content, $status);
    }

    /**
     * 宿主风格的 JSON 响应（HTTP 状态与业务 code 分开）。
     */
    protected function hostJson(int $code, string $message, int $status = 200): JsonResponse
    {
        return new JsonResponse([
            'code' => $code,
            'message' => $message,
            'request_id' => '9b9e08ab-48e5-4efa-83e7-97e5e3fe3d0c',
            'data' => (object) [],
        ], $status);
    }

    /**
     * 用全部默认规则检测，返回命中的规则标识。
     *
     * @return list<string>
     */
    protected function hitIds(Request $request, Response $response, array $actions = self::ALL_ON): array
    {
        return array_map(
            fn (RuleHit $hit) => $hit->rule,
            app(Inspector::class)->inspect($request, $response, $actions),
        );
    }
}
