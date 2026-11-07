<?php

namespace Maximus\Fail2Ban\Rules;

use Illuminate\Http\Request;
use Maximus\Fail2Ban\Contracts\Rule;
use Maximus\Fail2Ban\Rules\Concerns\UsesPatternList;
use Maximus\Fail2Ban\Rules\Support\PatternList;
use Maximus\Fail2Ban\Rules\Support\Subject;
use Symfony\Component\HttpFoundation\Response;

/**
 * 敏感文件探测：响应是 404，且路径指向环境与配置文件、版本库目录、备份与数据库导出、
 * 常见后台入口、后门与宿主不使用的脚本后缀、Laravel 的日志目录与调试运维面板。
 *
 * 清单见 resources/rules/sensitive-paths.txt；宿主可在 fail2ban.lists.sensitive-path 里追加或排除条目。
 */
class SensitivePath implements Rule
{
    use UsesPatternList;

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
        return '请求不存在的敏感地址（响应 404）时记一次，例如 .env、.git、数据库备份、phpMyAdmin、.php 脚本、Laravel 日志与调试面板；同一路径只算一次，不看查询参数。';
    }

    public function isPathRule(): bool
    {
        return true;
    }

    public function matches(Request $request, Response $response): bool
    {
        if ($response->getStatusCode() !== 404) {
            return false;
        }

        return PatternList::test($this->compiled()['regex'], Subject::of($request)->pathCandidates());
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
     * @return array{regex: string}
     */
    public static function compile(array $entries): array
    {
        return ['regex' => PatternList::regex($entries)];
    }

    protected static function file(): string
    {
        return dirname(__DIR__, 2).'/resources/rules/sensitive-paths.txt';
    }
}
