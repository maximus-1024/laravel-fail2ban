<?php

namespace Maximus\Fail2Ban\Http;

use Carbon\CarbonImmutable;
use Maximus\Fail2Ban\Contracts\AuditRepository;
use Maximus\Fail2Ban\Contracts\Rule;
use Maximus\Fail2Ban\Contracts\SettingsRepository;
use Maximus\Fail2Ban\Inspector;

/**
 * 把存储层的记录转成面板接口的形状。
 *
 * 存储层的时间是时间戳，接口里是带时区的 ISO 8601；规则在存储里是标识，
 * 接口里是 RuleRef { id, name }。访客可控的字符串原样返回，前端只按文字渲染。
 */
class Presenter
{
    /**
     * 本次请求里的运行设置（生成 reason 用），只读一次。
     */
    protected ?array $settings = null;

    public function __construct(
        protected Inspector $inspector,
        protected SettingsRepository $settingsRepository,
    ) {}

    /**
     * 时间戳转 ISO 8601（应用时区）；null 原样返回。
     */
    public function time(?int $timestamp): ?string
    {
        if ($timestamp === null) {
            return null;
        }

        return CarbonImmutable::createFromTimestamp($timestamp)
            ->setTimezone(config('app.timezone') ?: 'UTC')
            ->toIso8601String();
    }

    /**
     * RuleRef。规则显示名的回退只在这里：历史记录里的规则可能已不存在（例如宿主去掉了自定义规则），
     * 这时名称用标识本身。
     */
    public function rule(?string $id): ?array
    {
        if ($id === null) {
            return null;
        }

        return ['id' => $id, 'name' => $this->inspector->rule($id)?->name() ?? $id];
    }

    /**
     * 列表里的 Incident。
     */
    public function incident(array $incident): array
    {
        return [
            'id' => $incident['id'],
            'time' => $this->time($incident['time']),
            'visitor' => $incident['visitor'],
            'region' => $incident['region'],
            'rule' => $this->rule($incident['rule']),
            'source' => $incident['source'],
            'count' => $incident['count'],
            'disposition' => $incident['disposition'],
            'observe' => (bool) $incident['observe'],
            'operator' => $incident['operator'],
            'note' => $incident['note'],
        ];
    }

    /**
     * 事件详情：Incident 加攻击者信息；$ban 是这个访客当前的封禁记录（BanRepository::find()），
     * 事件编号相同才是同一次封禁，此时并入被拦次数、最近被拦时间与剩余秒数。
     */
    public function incidentDetail(array $incident, ?array $ban): array
    {
        $live = $ban !== null && $ban['incident'] === $incident['id'] ? $ban : null;

        $unbanAt = $live['unban_at'] ?? $incident['unban_at'];

        return $this->incident($incident) + [
            'reason' => $this->reason($incident),
            'user_agent' => $incident['user_agent'],
            'first_hit_at' => $this->time($incident['first_hit_at']),
            'banned_at' => $this->time($live['banned_at'] ?? $incident['banned_at']),
            'unban_at' => $this->time($unbanAt),
            'remaining_seconds' => $live ? $this->remaining($live['unban_at']) : null,
            'ban_minutes' => $live['ban_minutes'] ?? $incident['ban_minutes'],
            'offense' => $incident['offense'],
            'blocked' => $live ? (int) $live['blocked'] : null,
            'last_blocked_at' => $live ? $this->time($live['last_blocked_at']) : null,
            'other_rules' => $this->otherRules($incident['other_rules'] ?? []),
            'requests' => array_map(fn (array $request) => [
                'time' => $this->time((int) $request['time']),
                'method' => $request['method'],
                'path' => $request['path'],
            ], $incident['requests'] ?? []),
        ];
    }

    /**
     * 封禁列表里的 Ban。
     */
    public function ban(array $ban): array
    {
        return [
            'visitor' => $ban['visitor'],
            'visitor_note' => str_ends_with($ban['visitor'], '/64') ? 'IPv6 按 64 位网段封禁' : null,
            'region' => $ban['region'],
            'rule' => $this->rule($ban['rule']),
            'source' => $ban['source'],
            'reason' => $this->reason($ban),
            'banned_at' => $this->time($ban['banned_at']),
            'unban_at' => $this->time($ban['unban_at']),
            'remaining_seconds' => $this->remaining($ban['unban_at']),
            'total_seconds' => max(0, $ban['unban_at'] - $ban['banned_at']),
            'blocked' => (int) $ban['blocked'],
            'offense' => $ban['offense'],
            'incident_id' => $ban['incident'],
            'operator' => $ban['operator'],
            'note' => $ban['note'],
        ];
    }

    /**
     * 白名单的面板条目。
     */
    public function allowEntry(array $entry): array
    {
        return [
            'entry' => $entry['entry'],
            'note' => $entry['note'],
            'added_by' => $entry['added_by'],
            'added_at' => $this->time($entry['added_at']),
        ];
    }

    /**
     * 一条操作日志。detail 在存储里可以是结构化的（Operations 写入的 {text, ...}），
     * 接口里只给人看的那句话；没注明来源的按面板。
     */
    public function audit(array $entry): array
    {
        $detail = $entry['detail'] ?? null;

        return [
            'time' => $this->time((int) $entry['time']),
            'operator' => (string) $entry['operator'],
            'action' => $entry['action'],
            'target' => (string) ($entry['target'] ?? ''),
            'detail' => is_array($detail) ? (string) ($detail['text'] ?? '') : (string) ($detail ?? ''),
            'via' => ($entry['via'] ?? null) === AuditRepository::VIA_CONSOLE ? AuditRepository::VIA_CONSOLE : AuditRepository::VIA_PANEL,
        ];
    }

    /**
     * 给人看的一句触发条件：「10 分钟内 3 个不同地址」「命中 1 次即封」「由 admin 操作：备注」。
     *
     * 自动事件的次数取触发时记下的命中次数，时间范围取这条规则当前的设置（存储里没有记下触发时的时间范围）。
     */
    public function reason(array $record): ?string
    {
        if (($record['source'] ?? 'auto') === 'manual') {
            $operator = $record['operator'] ?? 'unknown';

            return filled($record['note'] ?? null)
                ? "由 {$operator} 操作：{$record['note']}"
                : "由 {$operator} 操作";
        }

        $rule = $record['rule'] ?? null;

        if ($rule === null) {
            return null;
        }

        $setting = $this->settings()['rules'][$rule] ?? null;
        $count = $record['count'] ?? $setting['count'] ?? null;

        if ($count === null) {
            return null;
        }

        if ((int) $count === 1) {
            return '命中 1 次即封';
        }

        $unit = $this->unit($rule);

        return $setting !== null
            ? "{$setting['window']} 分钟内 {$count} {$unit}"
            : "命中 {$count} {$unit}";
    }

    /**
     * 其它规则当时的命中条数。
     */
    protected function otherRules(array $rules): array
    {
        $list = [];

        foreach ($rules as $id => $count) {
            $list[] = ['id' => (string) $id, 'name' => $this->rule((string) $id)['name'], 'count' => (int) $count];
        }

        return $list;
    }

    protected function remaining(int $unbanAt): int
    {
        return max(0, $unbanAt - CarbonImmutable::now()->getTimestamp());
    }

    protected function settings(): array
    {
        return $this->settings ??= $this->settingsRepository->all();
    }

    /**
     * 「怎么算一次」的量词，由规则自己的 countMode() 决定，不写死规则清单：
     * 每次请求都算的是「次」，按去重键算的是「个不同地址」。规则已不存在时按「次」。
     */
    protected function unit(string $id): string
    {
        return $this->inspector->rule($id)?->countMode() === Rule::COUNT_DISTINCT ? '个不同地址' : '次';
    }
}
