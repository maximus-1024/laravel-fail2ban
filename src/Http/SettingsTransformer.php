<?php

namespace Maximus\Fail2Ban\Http;

use Illuminate\Validation\ValidationException;
use Maximus\Fail2Ban\Contracts\SettingsRepository;
use Maximus\Fail2Ban\Contracts\StatsRepository;
use Maximus\Fail2Ban\Inspector;

/**
 * 设置在接口与存储之间的转换（GET/PUT /settings）。
 *
 *  - 接口里 rules 是数组，每项带 id，字段叫 window_minutes、ban_minutes；
 *  - 存储里 rules 按规则标识做键，字段叫 window、ban。
 *
 * 数值范围与可选值的校验只在 SettingsRepository::save() 一处；
 * 这里只做形状转换，并把存储的错误键（rules.{标识}.window）转回接口的字段名
 * （rules.{提交数组里的下标}.window_minutes）。
 */
class SettingsTransformer
{
    /**
     * 接口字段 => 存储字段（规则内）。
     */
    public const RULE_FIELDS = [
        'action' => 'action',
        'window_minutes' => 'window',
        'count' => 'count',
        'ban_minutes' => 'ban',
    ];

    /**
     * 可写的顶层分组（存储里同名）。
     */
    public const SECTIONS = ['mode', 'rules', 'repeat', 'response'];

    public function __construct(
        protected Inspector $inspector,
        protected StatsRepository $stats,
        protected SettingsRepository $settings,
        protected Presenter $presenter,
    ) {}

    /**
     * 存储的设置 => 接口返回的形状。
     */
    public function toApi(array $settings): array
    {
        $limits = $this->settings->limits();
        $trend = collect($this->stats->trend(24));

        $rules = [];

        // 设置里的规则就是配置 fail2ban.rules 的键，按书写顺序；规则入口按同一份配置构建，每条都在。
        foreach ($settings['rules'] as $id => $values) {
            $rule = $this->inspector->rule($id);

            $rules[] = [
                'id' => $id,
                'name' => $rule->name(),
                'description' => $rule->description(),
                'count_mode' => $rule->countMode(),
                'action' => $values['action'],
                'window_minutes' => (int) $values['window'],
                'count' => (int) $values['count'],
                'ban_minutes' => (int) $values['ban'],
                'hits_24h' => $trend->sum(fn (array $hour) => $hour['rules'][$id] ?? 0),
            ];
        }

        return [
            'enabled' => (bool) config('fail2ban.enabled'),
            'mode' => $settings['mode'],
            'rules' => $rules,
            'repeat' => $settings['repeat'],
            'response' => $settings['response'],
            'limits' => [
                'window_minutes' => $limits['window'],
                'count' => $limits['count'],
                'ban_minutes' => $limits['ban'],
                'factor' => $limits['factor'],
                'max_days' => $limits['max_days'],
                'keep_days' => $limits['keep_days'],
                'statuses' => $limits['statuses'],
                'message' => $limits['message'],
            ],
            'updated_by' => $settings['updated_by'],
            'updated_at' => $this->presenter->time($settings['updated_at']),
        ];
    }

    /**
     * 接口提交的改动 => 存储的改动。
     *
     * 形状不对（rules 不是数组、某项缺 id 或 id 不认识、出现不可写的字段）时直接抛 422，
     * 错误键是接口字段名。数值范围不在这里查。
     *
     * @return array{0: array, 1: array<string, string>} [存储形状的改动, 存储点号路径 => 接口点号路径]
     *
     * @throws \Illuminate\Validation\ValidationException
     */
    public function fromApi(array $input): array
    {
        $changes = [];
        $paths = [];
        $errors = [];

        foreach ($input as $key => $value) {
            if (! in_array($key, self::SECTIONS, true)) {
                $errors[$key][] = '这一项不能修改。';

                continue;
            }

            if ($key !== 'rules') {
                $changes[$key] = $value;

                continue;
            }

            if (! is_array($value) || ! array_is_list($value)) {
                $errors['rules'][] = '必须是规则数组。';

                continue;
            }

            foreach ($value as $index => $item) {
                $id = is_array($item) ? ($item['id'] ?? null) : null;

                if (! is_string($id) || ! array_key_exists($id, $this->settings->defaults()['rules'])) {
                    $errors["rules.{$index}.id"][] = '未知的规则。';

                    continue;
                }

                foreach ($item as $field => $fieldValue) {
                    if ($field === 'id') {
                        continue;
                    }

                    if (! isset(self::RULE_FIELDS[$field])) {
                        $errors["rules.{$index}.{$field}"][] = '这一项不能修改。';

                        continue;
                    }

                    $stored = self::RULE_FIELDS[$field];

                    $changes['rules'][$id][$stored] = $fieldValue;
                    $paths["rules.{$id}.{$stored}"] = "rules.{$index}.{$field}";
                }
            }
        }

        if ($errors !== []) {
            throw ValidationException::withMessages($errors);
        }

        return [$changes, $paths];
    }

    /**
     * 把存储的错误键转回接口的字段名。
     *
     * @param  array<string, list<string>>  $errors
     * @param  array<string, string>  $paths
     * @return array<string, list<string>>
     */
    public function errorsToApi(array $errors, array $paths): array
    {
        $mapped = [];

        foreach ($errors as $key => $messages) {
            $mapped[$paths[$key] ?? $key] = $messages;
        }

        return $mapped;
    }
}
