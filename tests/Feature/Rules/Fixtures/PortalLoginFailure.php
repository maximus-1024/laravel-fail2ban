<?php

namespace Maximus\Fail2Ban\Tests\Feature\Rules\Fixtures;

use Illuminate\Contracts\Config\Repository as Config;
use Illuminate\Http\Request;
use Maximus\Fail2Ban\Contracts\Rule;
use Symfony\Component\HttpFoundation\Response;

/**
 * 测试用的自定义规则（不是地址类）：登录接口返回 401 时每次都算。
 * 构造函数要一个依赖，证明自定义规则由容器解析。
 */
class PortalLoginFailure implements Rule
{
    public function __construct(private readonly Config $config)
    {
    }

    public function id(): string
    {
        return 'login-failure';
    }

    public function name(): string
    {
        return '登录失败';
    }

    public function description(): string
    {
        return '登录接口返回 401 时每次都记一次。';
    }

    public function isPathRule(): bool
    {
        return false;
    }

    public function matches(Request $request, Response $response): bool
    {
        return $response->getStatusCode() === 401
            && $request->getPathInfo() === $this->config->get('fail2ban-test.login_path', '/portal/api/login');
    }

    public function key(Request $request): ?string
    {
        return null;
    }

    public function countMode(): string
    {
        return self::COUNT_EACH;
    }
}
