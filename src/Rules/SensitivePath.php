<?php

namespace Maximus\Fail2Ban\Rules;

use Illuminate\Http\Request;
use Maximus\Fail2Ban\Contracts\Rule;
use Maximus\Fail2Ban\Rules\Concerns\MatchesPathsByStatus;
use Maximus\Fail2Ban\Rules\Support\Subject;
use Symfony\Component\HttpFoundation\Response;

/**
 * 敏感文件探测：路径指向敏感地址。清单按分段分两类（见 MatchesPathsByStatus）：
 *  - 不看状态码：环境与配置文件、版本库目录、备份与数据库导出、后门与宿主不使用的脚本后缀、
 *    Laravel 的日志、缓存与会话文件；
 *  - 响应不是成功（不在 200–399）时才算：常见后台入口、Laravel 的调试与运维面板、其它平台的已知漏洞地址。
 *
 * 清单见 resources/rules/sensitive-paths.txt；宿主可在 fail2ban.lists.sensitive-path 里追加或排除条目。
 */
class SensitivePath implements Rule
{
    use MatchesPathsByStatus;

    public function id(): string
    {
        return 'sensitive-path';
    }

    public function name(): string
    {
        return '敏感文件探测';
    }

    public function description(): string
    {
        return '请求敏感地址时记一次：.env、.git、数据库备份、.php 脚本、Laravel 日志等不看响应状态；phpMyAdmin 等后台入口与 Horizon 等调试运维面板只在响应不是成功（如 401、403、404）时算。同一路径只算一次，不看查询参数。';
    }

    public function isPathRule(): bool
    {
        return true;
    }

    public function matches(Request $request, Response $response): bool
    {
        return $this->matchesPathList(Subject::of($request), $response->getStatusCode());
    }

    public function key(Request $request): ?string
    {
        return Subject::key(Subject::of($request)->path());
    }

    public function countMode(): string
    {
        return self::COUNT_DISTINCT;
    }

    /**
     * @param  array{any-status: list<string>, non-success: list<string>}  $entries
     * @return array{any: string, any_gate: list<string>, non_success: string, non_success_gate: list<string>}
     */
    public static function compile(array $entries): array
    {
        return static::compilePaths($entries);
    }

    protected static function file(): string
    {
        return dirname(__DIR__, 2).'/resources/rules/sensitive-paths.txt';
    }
}
