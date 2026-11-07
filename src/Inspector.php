<?php

namespace Maximus\Fail2Ban;

use Illuminate\Contracts\Container\Container;
use Illuminate\Http\Request;
use InvalidArgumentException;
use Maximus\Fail2Ban\Contracts\Rule;
use Maximus\Fail2Ban\Rules\AttackPattern;
use Maximus\Fail2Ban\Rules\KnownExploit;
use Maximus\Fail2Ban\Rules\NotFoundScan;
use Maximus\Fail2Ban\Rules\ScannerAgent;
use Maximus\Fail2Ban\Rules\SensitivePath;
use Symfony\Component\HttpFoundation\Response;

/**
 * 规则入口：给它请求、响应和各规则当前的动作，返回本次请求的命中清单。
 *
 *  - 动作为 "off" 的规则跳过，不检测；"observe" 与 "ban" 照常检测。动作表里没有的规则按 "off"。
 *  - 地址类规则按登记顺序只记第一条命中（已知漏洞探测 → 敏感文件探测 → 404 扫描）。
 *    排在前面的规则被关闭时不参与这个先后，后面的规则照常检测。
 *  - 扫描器特征与攻击特征与地址类规则各记各的。
 *
 * 纯逻辑：不碰 Redis，不读请求正文。构造时不做任何事，清单在第一次用到时才加载。
 *
 * 可扩展：从容器解析出来的实例（app(Inspector::class)）由 fromConfig() 按
 * config/fail2ban.php 构建，带上宿主追加、排除的清单条目（lists）与登记的自定义规则（rules.*.class）。
 */
class Inspector
{
    /**
     * 检测的动作。其它值（"off"、缺失、拼错）都不检测。
     */
    public const DETECTING_ACTIONS = ['ban', 'observe'];

    /**
     * @var array<string, \Maximus\Fail2Ban\Contracts\Rule>
     */
    protected array $rules = [];

    /**
     * @param  iterable<\Maximus\Fail2Ban\Contracts\Rule>  $rules  检测顺序
     */
    public function __construct(iterable $rules)
    {
        foreach ($rules as $rule) {
            if (isset($this->rules[$rule->id()])) {
                throw new InvalidArgumentException("Duplicate fail2ban rule [{$rule->id()}].");
            }

            $this->rules[$rule->id()] = $rule;
        }
    }

    /**
     * 内置的五条规则：标识 => 类，按检测顺序排列。地址类规则的先后就是这个顺序。
     */
    public const BUILTIN = [
        'known-exploit' => KnownExploit::class,
        'sensitive-path' => SensitivePath::class,
        'not-found-scan' => NotFoundScan::class,
        'scanner-agent' => ScannerAgent::class,
        'attack-pattern' => AttackPattern::class,
    ];

    /**
     * 可以在 fail2ban.lists 里追加、排除清单条目的内置规则。
     */
    public const LIST_RULES = ['known-exploit', 'sensitive-path', 'scanner-agent'];

    /**
     * 按 fail2ban 配置构建（服务提供者里的容器绑定用这个）。
     *
     *  - lists.{规则标识}.extra / extra_any_status / except：给 LIST_RULES 里的规则追加、排除清单条目。
     *    地址清单里 extra 归「响应不是成功才算」，extra_any_status 归「不看状态码」；except 两类都排除。
     *  - rules.{标识}.class：登记自定义规则类（由容器解析，可以注入依赖），它的 id() 必须等于标识；
     *    写在内置规则的标识下面则替换那条内置规则（类要返回同样的标识）。
     *
     * 检测顺序：已知漏洞探测、敏感文件探测、自定义的地址类规则、404 扫描、扫描器特征、攻击特征、
     * 自定义的其它规则。404 扫描是「任何 404」的兜底，所以自定义地址类规则排在它前面，否则永远轮不到。
     *
     * 配置写错（类不存在、没实现 Rule、标识对不上、lists 里写了不认识的规则）时抛 InvalidArgumentException，
     * 不静默忽略：排除条目是宿主处理误伤的出口，写错了却不报错会让人以为已经生效。
     *
     * @param  array<string, mixed>  $config  config('fail2ban')
     */
    public static function fromConfig(array $config, Container $container): static
    {
        $lists = (array) ($config['lists'] ?? []);

        foreach (array_keys($lists) as $id) {
            if (! in_array($id, static::LIST_RULES, true)) {
                throw new InvalidArgumentException("Fail2Ban list [{$id}] is not supported. Lists can be customized for: ".implode(', ', static::LIST_RULES).'.');
            }
        }

        $classes = static::BUILTIN;
        $custom = [];

        foreach ((array) ($config['rules'] ?? []) as $id => $settings) {
            $class = is_array($settings) ? ($settings['class'] ?? null) : null;

            if ($class === null) {
                if (! isset(static::BUILTIN[$id])) {
                    throw new InvalidArgumentException("Fail2Ban rule [{$id}] needs a [class] that implements ".Rule::class.'.');
                }

                continue;
            }

            if (! is_string($class) || ! class_exists($class) || ! is_subclass_of($class, Rule::class)) {
                throw new InvalidArgumentException("Fail2Ban rule [{$id}] class must implement ".Rule::class.'.');
            }

            if (isset(static::BUILTIN[$id])) {
                $classes[$id] = $class;
            } else {
                $custom[$id] = $class;
            }
        }

        $builtin = [];

        foreach ($classes as $id => $class) {
            $builtin[$id] = static::makeRule($id, $class, isset($lists[$id]) ? (array) $lists[$id] : null, $container);
        }

        $customPath = [];
        $customOther = [];

        foreach ($custom as $id => $class) {
            $rule = static::makeRule($id, $class, isset($lists[$id]) ? (array) $lists[$id] : null, $container);

            if ($rule->isPathRule()) {
                $customPath[] = $rule;
            } else {
                $customOther[] = $rule;
            }
        }

        return new static([
            $builtin['known-exploit'],
            $builtin['sensitive-path'],
            ...$customPath,
            $builtin['not-found-scan'],
            $builtin['scanner-agent'],
            $builtin['attack-pattern'],
            ...$customOther,
        ]);
    }

    /**
     * 建一条规则：清单规则带上宿主追加、排除的条目。
     *
     * 内置规则类没有依赖，宿主也没在容器里改绑它时直接 new，省掉容器的反射——php-fpm 下
     * 每个请求都要建一次规则入口。其它类（自定义规则、替换内置规则的类）由容器解析，可以注入依赖。
     *
     * @param  array{extra?: mixed, extra_any_status?: mixed, except?: mixed}|null  $list  fail2ban.lists.{标识}
     */
    protected static function makeRule(string $id, string $class, ?array $list, Container $container): Rule
    {
        $parameters = $list === null ? [] : [
            'extra' => array_values((array) ($list['extra'] ?? [])),
            'except' => array_values((array) ($list['except'] ?? [])),
            'extraAnyStatus' => array_values((array) ($list['extra_any_status'] ?? [])),
        ];

        if ((static::BUILTIN[$id] ?? null) === $class && ! $container->bound($class)) {
            return $list === null ? new $class : new $class($parameters['extra'], $parameters['except'], $parameters['extraAnyStatus']);
        }

        $rule = $container->make($class, $parameters);

        if ($rule->id() !== $id) {
            throw new InvalidArgumentException("Fail2Ban rule [{$id}] is registered with class [{$class}] whose id() is [{$rule->id()}].");
        }

        return $rule;
    }

    /**
     * 检测本次请求。
     *
     * @param  array<string, string>  $actions  规则标识 => 动作（"ban"、"observe"、"off"）
     * @return list<\Maximus\Fail2Ban\RuleHit>  命中的规则，按检测顺序；没有命中时为空数组
     */
    public function inspect(Request $request, Response $response, array $actions): array
    {
        $hits = [];
        $pathRuleHit = false;

        foreach ($this->rules as $id => $rule) {
            if (! in_array($actions[$id] ?? 'off', static::DETECTING_ACTIONS, true)) {
                continue;
            }

            $isPathRule = $rule->isPathRule();

            if ($isPathRule && $pathRuleHit) {
                continue;
            }

            if ($rule->matches($request, $response)) {
                $hits[] = RuleHit::make($rule, $request);
                $pathRuleHit = $pathRuleHit || $isPathRule;
            }
        }

        return $hits;
    }

    /**
     * 全部规则，标识 => 规则，按检测顺序。面板取中文名与说明用。
     *
     * @return array<string, \Maximus\Fail2Ban\Contracts\Rule>
     */
    public function rules(): array
    {
        return $this->rules;
    }

    /**
     * 按标识取一条规则。
     */
    public function rule(string $id): ?Rule
    {
        return $this->rules[$id] ?? null;
    }
}
