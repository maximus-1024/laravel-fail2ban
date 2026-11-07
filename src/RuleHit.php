<?php

namespace Maximus\Fail2Ban;

use Carbon\CarbonImmutable;
use Illuminate\Http\Request;
use Maximus\Fail2Ban\Contracts\Rule;
use Maximus\Fail2Ban\Rules\Support\Redactor;
use Maximus\Fail2Ban\Rules\Support\Subject;
use Maximus\Fail2Ban\Support\Text;

/**
 * 一次规则命中：哪条规则、去重键、展示用的请求记录。由 Inspector::inspect() 产生。
 */
final class RuleHit
{
    /**
     * @param  string  $rule  规则标识，例如 "sensitive-path"
     * @param  string|null  $key  去重键；null 表示「每次请求都算」
     * @param  string  $method  请求行上真实的方法，大写
     * @param  string  $path  「路径加查询参数」，凭据参数的值已打码（Redactor），已按 fail2ban.path_max 截断
     * @param  int  $time  检测时刻（时间戳）
     */
    public function __construct(
        public readonly string $rule,
        public readonly ?string $key,
        public readonly string $method,
        public readonly string $path,
        public readonly int $time,
    ) {
    }

    /**
     * 为命中的规则生成一条记录。只在有命中时调用，打码与截断的开销不落在正常请求上。
     */
    public static function make(Rule $rule, Request $request): self
    {
        $subject = Subject::of($request);

        return new self(
            $rule->id(),
            $rule->key($request),
            $subject->method(),
            Text::path(Redactor::uri($subject->uri())),
            // 不用 Date::now()：多一次转换；CarbonImmutable::now() 同样认测试时间。
            CarbonImmutable::now()->getTimestamp(),
        );
    }

    /**
     * 展示用的请求记录（存进命中记录、攻击事件里的那一条），原样存储。
     *
     * @return array{time: int, method: string, path: string}
     */
    public function record(): array
    {
        return [
            'time' => $this->time,
            'method' => $this->method,
            'path' => $this->path,
        ];
    }
}
