<?php

namespace Maximus\Fail2Ban\Tests\Feature\Rules\Fixtures;

use Illuminate\Http\Request;
use Maximus\Fail2Ban\Contracts\Rule;
use Symfony\Component\HttpFoundation\Response;

/**
 * 测试用的自定义地址类规则：请求已下线的 /api/v0/ 接口（404）时按不同路径计数。
 */
class LegacyApiPath implements Rule
{
    public function id(): string
    {
        return 'legacy-api';
    }

    public function name(): string
    {
        return '旧版接口探测';
    }

    public function description(): string
    {
        return '请求已下线的 /api/v0/ 接口（响应 404）时记一次；同一路径只算一次。';
    }

    public function isPathRule(): bool
    {
        return true;
    }

    public function matches(Request $request, Response $response): bool
    {
        return $response->getStatusCode() === 404 && str_starts_with($request->getPathInfo(), '/api/v0/');
    }

    public function key(Request $request): ?string
    {
        return $request->getPathInfo();
    }

    public function countMode(): string
    {
        return self::COUNT_DISTINCT;
    }
}
