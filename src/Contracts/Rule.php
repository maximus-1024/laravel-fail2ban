<?php

namespace Maximus\Fail2Ban\Contracts;

use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * 一条检测规则，一条规则一个类，写法参照 Laravel 的校验规则类。
 *
 * 规则是纯逻辑：只看请求与响应，不碰 Redis、不改请求、不抛业务异常。
 * 多条规则怎么组织、规则先后、动作为 off 的跳过，由 Maximus\Fail2Ban\Inspector 负责。
 *
 * 宿主程序的自定义规则也实现这个接口，在 config/fail2ban.php 的 rules 里登记（见 README）。
 * matches() 对每个请求都会调用，要先做最便宜的判断，正常请求应在几微秒内返回 false。
 */
interface Rule
{
    /**
     * countMode() 的取值：每个不同的去重键（key() 的返回值）算一次。面板显示为「个不同地址」。
     */
    public const COUNT_DISTINCT = 'distinct';

    /**
     * countMode() 的取值：每次请求都算一次（key() 返回 null）。面板显示为「次」。
     */
    public const COUNT_EACH = 'each';

    /**
     * 规则标识，例如 "not-found-scan"。出现在设置、统计、事件和 Redis 键里。
     */
    public function id(): string;

    /**
     * 中文名，例如「404 扫描」。面板的规则表与编辑抽屉显示。
     */
    public function name(): string;

    /**
     * 一句给运维看的说明：什么时候算命中、怎么算一次。面板的规则表与编辑抽屉显示。
     */
    public function description(): string;

    /**
     * 是不是地址类规则。地址类规则之间只记最靠前的一条。
     */
    public function isPathRule(): bool;

    /**
     * 本次请求是否命中这条规则。
     *
     * 只读取请求行、查询参数和请求头，不读请求正文。
     */
    public function matches(Request $request, Response $response): bool;

    /**
     * 命中时的去重键（怎么算一次）。只在 matches() 为 true 时有意义。
     *
     * 返回 null 表示「每次请求都算」；返回字符串时，同一访客在这条规则下
     * 同一个键只记一次。
     */
    public function key(Request $request): ?string;

    /**
     * 出现次数怎么数：Rule::COUNT_DISTINCT（不同的去重键各算一次）或 Rule::COUNT_EACH（每次请求都算）。
     *
     * 必须与 key() 一致：COUNT_EACH 的规则 key() 返回 null，COUNT_DISTINCT 的规则 key() 返回字符串。
     * 面板用它决定「出现次数」后面写「个不同地址」还是「次」。
     */
    public function countMode(): string;
}
