<?php

namespace Maximus\Fail2Ban\Repositories;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Redis\Factory as RedisFactory;
use Illuminate\Validation\ValidationException;
use Maximus\Fail2Ban\Contracts\SettingsRepository;
use Maximus\Fail2Ban\Repositories\Concerns\InteractsWithRedis;

class RedisSettingsRepository implements SettingsRepository
{
    use InteractsWithRedis;

    /**
     * 设置哈希的键。字段是点号路径，如 rules.not-found-scan.count。
     */
    public const KEY = 'fail2ban:settings';

    public const MODES = ['off', 'observe', 'block'];

    public const ACTIONS = ['ban', 'observe', 'off'];

    public const STATUSES = [403, 429, 404];

    public const MESSAGE_MAX = 500;

    /**
     * Create a new repository instance.
     */
    public function __construct(RedisFactory $redis)
    {
        $this->redis = $redis;
    }

    public function all(): array
    {
        return $this->resolve($this->connection()->hgetall(self::KEY) ?: []);
    }

    public function defaults(): array
    {
        $settings = [];

        foreach ($this->fields() as $field => $schema) {
            $raw = data_get(config('fail2ban'), $field);

            // 配置文件是可信来源：取规范化后的值；万一越界也照原样用，不静默改掉。
            [$value, $error] = $this->check($field, $raw, $schema);

            data_set($settings, $field, $error === null ? $value : $raw);
        }

        return $settings + ['updated_by' => null, 'updated_at' => null];
    }

    public function resolve(array $stored): array
    {
        $settings = $this->defaults();

        foreach ($this->fields() as $field => $schema) {
            if (! array_key_exists($field, $stored)) {
                continue;
            }

            [$value, $error] = $this->check($field, $stored[$field], $schema);

            if ($error === null) {
                data_set($settings, $field, $value);
            }
        }

        $settings['updated_by'] = isset($stored['updated_by']) ? (string) $stored['updated_by'] : null;
        $settings['updated_at'] = isset($stored['updated_at']) ? (int) $stored['updated_at'] : null;

        return $settings;
    }

    public function save(array $changes, string $actor): array
    {
        [$values, $errors] = $this->normalize($changes);

        if ($errors !== []) {
            throw ValidationException::withMessages($errors);
        }

        $fields = array_map(fn ($value) => is_bool($value) ? ($value ? '1' : '0') : (string) $value, $values);

        $fields['updated_by'] = $actor;
        $fields['updated_at'] = (string) CarbonImmutable::now()->getTimestamp();

        $this->connection()->hmset(self::KEY, $fields);

        return $this->all();
    }

    public function limits(): array
    {
        return [
            'window' => [1, 1440],
            'count' => [1, $this->hitsMax()],
            'ban' => [1, 43200],
            'factor' => [2, 10],
            'max_days' => [1, 30],
            'keep_days' => [1, 30],
            'statuses' => self::STATUSES,
            'message' => [1, self::MESSAGE_MAX],
        ];
    }

    /**
     * 把改动拍平成点号路径并逐项校验。
     *
     * @return array{0: array<string, mixed>, 1: array<string, list<string>>} [规范化后的值, 错误]
     */
    protected function normalize(array $changes): array
    {
        $fields = $this->fields();
        $values = [];
        $errors = [];

        foreach ($this->flatten($changes) as $field => $value) {
            if (! isset($fields[$field])) {
                $errors[$field][] = '未知的设置项。';

                continue;
            }

            [$normalized, $error] = $this->check($field, $value, $fields[$field]);

            if ($error !== null) {
                $errors[$field][] = $error;
            } else {
                $values[$field] = $normalized;
            }
        }

        return [$values, $errors];
    }

    /**
     * 拍平成点号路径。叶子是标量或 null；空数组也当叶子（会被判为不合法）。
     */
    protected function flatten(array $changes, string $prefix = ''): array
    {
        $flat = [];

        foreach ($changes as $key => $value) {
            $path = $prefix.$key;

            if (is_array($value) && $value !== []) {
                $flat += $this->flatten($value, $path.'.');
            } else {
                $flat[$path] = $value;
            }
        }

        return $flat;
    }

    /**
     * 每个可保存的设置项及其约束。
     *
     * @return array<string, array{type: string, min?: int, max?: int, in?: list<mixed>}>
     */
    protected function fields(): array
    {
        $limits = $this->limits();

        $fields = ['mode' => ['type' => 'enum', 'in' => self::MODES]];

        foreach (array_keys((array) config('fail2ban.rules')) as $rule) {
            $fields["rules.{$rule}.action"] = ['type' => 'enum', 'in' => self::ACTIONS];

            foreach (['window', 'count', 'ban'] as $name) {
                $fields["rules.{$rule}.{$name}"] = ['type' => 'int', 'min' => $limits[$name][0], 'max' => $limits[$name][1]];
            }
        }

        $fields['repeat.enabled'] = ['type' => 'bool'];

        foreach (['factor', 'max_days', 'keep_days'] as $name) {
            $fields["repeat.{$name}"] = ['type' => 'int', 'min' => $limits[$name][0], 'max' => $limits[$name][1]];
        }

        $fields['response.status'] = ['type' => 'enum', 'in' => self::STATUSES];
        $fields['response.message'] = ['type' => 'string', 'max' => $limits['message'][1]];

        foreach (['show_ip', 'show_incident', 'show_time'] as $name) {
            $fields["response.{$name}"] = ['type' => 'bool'];
        }

        return $fields;
    }

    /**
     * 校验并规范化一个值。
     *
     * @return array{0: mixed, 1: string|null} [规范化后的值, 错误]
     */
    protected function check(string $field, mixed $value, array $schema): array
    {
        switch ($schema['type']) {
            case 'int':
                $int = $this->toInt($value);

                return $int !== null && $int >= $schema['min'] && $int <= $schema['max']
                    ? [$int, null]
                    : [null, "必须是 {$schema['min']} 到 {$schema['max']} 之间的整数。"];

            case 'bool':
                $bool = is_bool($value) ? $value : filter_var($value, FILTER_VALIDATE_BOOL, FILTER_NULL_ON_FAILURE);

                return $bool === null || is_array($value) ? [null, '必须是开或关。'] : [$bool, null];

            case 'enum':
                foreach ($schema['in'] as $option) {
                    if (is_int($option) ? $this->toInt($value) === $option : $value === $option) {
                        return [$option, null];
                    }
                }

                return [null, '必须是 '.implode('、', $schema['in']).' 之一。'];

            case 'string':
                return is_string($value) && trim($value) !== '' && mb_strlen($value) <= $schema['max']
                    ? [$value, null]
                    : [null, "必须是 1 到 {$schema['max']} 个字符的文字。"];
        }

        return [null, '未知的设置项。'];
    }

    /**
     * 整数或整数形式的字符串；其它（小数、布尔、空串）返回 null。
     */
    protected function toInt(mixed $value): ?int
    {
        if (is_int($value)) {
            return $value;
        }

        if (is_string($value) && preg_match('/^-?\d+$/', trim($value))) {
            return (int) trim($value);
        }

        return null;
    }

    protected function hitsMax(): int
    {
        return max(1, (int) config('fail2ban.hits_max', 100));
    }
}
