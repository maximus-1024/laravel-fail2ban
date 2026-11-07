<?php

namespace Maximus\Fail2Ban\Rules;

use Illuminate\Http\Request;
use Maximus\Fail2Ban\Contracts\Rule;
use Maximus\Fail2Ban\Rules\Support\Subject;
use Symfony\Component\HttpFoundation\Response;

/**
 * 404 扫描：响应是 404 就算。
 *
 * 「且没有命中另外两条地址类规则」由 Inspector 保证：地址类规则只记最靠前的一条，
 * 本规则排在已知漏洞探测与敏感文件探测之后。单独调用本类时，任何 404 都返回 true。
 */
class NotFoundScan implements Rule
{
    public function id(): string
    {
        return 'not-found-scan';
    }

    public function name(): string
    {
        return '404 扫描';
    }

    public function description(): string
    {
        return '请求的地址不存在（响应 404），且不属于已知漏洞探测或敏感文件探测时记一次；同一路径只算一次，不看查询参数。';
    }

    public function isPathRule(): bool
    {
        return true;
    }

    public function matches(Request $request, Response $response): bool
    {
        return $response->getStatusCode() === 404;
    }

    public function key(Request $request): ?string
    {
        return Subject::key(Subject::of($request)->path());
    }

    public function countMode(): string
    {
        return self::COUNT_DISTINCT;
    }
}
