<?php

namespace Maximus\Fail2Ban;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Http\Request;
use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Validator;
use Illuminate\Validation\ValidationException;
use InvalidArgumentException;
use Maximus\Fail2Ban\Contracts\AllowlistRepository;
use Maximus\Fail2Ban\Contracts\AuditRepository;
use Maximus\Fail2Ban\Contracts\BanRepository;
use Maximus\Fail2Ban\Contracts\IncidentRepository;
use Maximus\Fail2Ban\Contracts\SettingsRepository;
use Maximus\Fail2Ban\Contracts\StatsRepository;
use Maximus\Fail2Ban\Events\IpBanned;
use Maximus\Fail2Ban\Events\IpUnbanned;

/**
 * 运维操作：面板接口与三个命令共用的唯一一处实现。
 *
 * 每个改动操作都写一条操作日志，带操作人与来源 via（AuditRepository::VIA_PANEL | VIA_CONSOLE）。
 * detail 存成结构化内容 {text: 给人看的一句话, ...附加内容（如设置的旧值新值）}，面板接口只取 text。
 *
 * 输入不合法时抛 ValidationException，错误键与面板接口一致（ip、minutes、note、entry、
 * visitor，设置用存储的点号路径）；命令行把错误原样打印出来。
 *
 * 改动本身（封禁、解封、白名单、设置）写进 Redis 之后，后面的几步（标记事件、写攻击事件、统计、
 * 发出事件、操作日志）各自兜住异常（rescue()，经宿主的异常处理上报），不让其中一步的读超时或
 * 宿主监听器的异常把改动报成失败。
 *
 * 事件：手动封禁发 IpBanned（$ban['source'] 为 manual）；每解除一个封禁发一次 IpUnbanned
 * （面板或命令解封、加白名单时连带解封、切到拦截时解除观察期封禁）。
 */
class Operations
{
    /**
     * 备注的最大长度（手动封禁、白名单）。
     */
    public const NOTE_MAX = 200;

    public const MODE_LABELS = ['off' => '已关闭', 'observe' => '观察', 'block' => '拦截'];

    public const ACTION_LABELS = ['ban' => '封禁', 'observe' => '观察', 'off' => '关闭'];

    /**
     * 累犯加长与拦截响应各项在操作日志里的名字。
     */
    protected const FIELD_LABELS = [
        'repeat.enabled' => '累犯加长',
        'repeat.factor' => '累犯倍数',
        'repeat.max_days' => '累犯封顶',
        'repeat.keep_days' => '累犯记录保留',
        'response.status' => '拒绝状态码',
        'response.show_ip' => '显示访客 IP',
        'response.show_incident' => '显示事件编号',
        'response.show_time' => '显示记录时间',
    ];

    public function __construct(
        protected BanRepository $bans,
        protected AllowlistRepository $allowlist,
        protected IncidentRepository $incidents,
        protected AuditRepository $audit,
        protected SettingsRepository $settings,
        protected StatsRepository $stats,
        protected Inspector $inspector,
        protected Dispatcher $events,
    ) {}

    /**
     * 解封：删除封禁及相关记录，把对应攻击事件标成已解封，发 IpUnbanned（原因 manual），写操作日志。
     *
     * 访客当时没有被封时，存储层照样清掉命中记录与累犯记录，这里也照样写一条操作日志，
     * 返回 null（面板据此回 404，命令据此以失败退出）。
     *
     * @param  string  $visitor  IP 或访客键（IPv6 会换成 64 位网段）
     * @param  string|null  $because  解封原因（例如加入白名单），写进操作日志
     * @return array|null 被解除的封禁记录
     *
     * @throws \Illuminate\Validation\ValidationException 不是合法的 IP 或访客键（错误键 visitor）
     */
    public function unban(string $visitor, string $actor, string $via, ?string $because = null): ?array
    {
        return $this->release($this->visitorKey($visitor, 'visitor'), $actor, $via, $because, IpUnbanned::REASON_MANUAL);
    }

    /**
     * 解封的实现：unban() 与加白名单时的连带解封共用，$reason 是 IpUnbanned 的原因。
     */
    protected function release(string $key, string $actor, string $via, ?string $because, string $reason): ?array
    {
        $ban = $this->bans->unban($key);

        if ($ban !== null) {
            rescue(fn () => $this->incidents->markUnbanned($ban['incident']));
            rescue(fn () => $this->events->dispatch(new IpUnbanned($key, $ban, $actor, $via, $reason)));

            $minutes = (int) ceil(max(0, $ban['unban_at'] - CarbonImmutable::now()->getTimestamp()) / 60);
            $text = ($because ?? '提前解除')."，当时还剩 {$minutes} 分钟。事件 {$ban['incident']}";
        } else {
            $text = '当时没有封禁，已清除命中记录与累犯记录';
        }

        $this->record($actor, $via, 'unban', $key, $text, ['incident' => $ban['incident'] ?? null]);

        return $ban;
    }

    /**
     * 手动封禁：IP 不合法、在白名单里、被宿主豁免时拒绝；否则以这次为准写封禁、
     * 写攻击事件、记一次封禁统计、发 IpBanned、写操作日志。
     *
     * @param  bool  $requireNote  面板要求必填备注；命令行可以不填
     *
     * @return array 封禁记录（BanRepository 的形状）
     *
     * @throws \Illuminate\Validation\ValidationException 错误键 ip、minutes、note
     */
    public function ban(string $ip, mixed $minutes, ?string $note, string $actor, string $via, ?Request $request = null, bool $requireNote = false): array
    {
        [$min, $max] = $this->settings->limits()['ban'];

        $note = is_string($note) && trim($note) !== '' ? trim($note) : null;

        Validator::make(compact('ip', 'minutes', 'note'), [
            'ip' => ['required', 'string', 'ip'],
            'minutes' => ['required', 'integer', "min:{$min}", "max:{$max}"],
            'note' => [$requireNote ? 'required' : 'nullable', 'string', 'max:'.self::NOTE_MAX],
        ], [
            'ip.required' => '请填写 IP 地址。',
            'ip.ip' => '不是合法的 IP 地址。',
            'minutes.required' => '请填写封禁时长。',
            'minutes.integer' => "封禁时长必须是 {$min} 到 {$max} 之间的整数分钟。",
            'minutes.min' => "封禁时长必须是 {$min} 到 {$max} 之间的整数分钟。",
            'minutes.max' => "封禁时长必须是 {$min} 到 {$max} 之间的整数分钟。",
            'note.required' => '请填写备注。',
            'note.max' => '备注最多 '.self::NOTE_MAX.' 个字。',
        ])->validate();

        $ip = trim($ip);
        $key = Visitor::key($ip);

        // IPv6 封的是整个 /64：地址本身或网段首地址在白名单里都拒绝。
        if ($match = $this->allowlist->match($ip) ?? $this->allowlist->match(Visitor::address($key))) {
            throw ValidationException::withMessages([
                'ip' => ["这个地址在白名单里（{$match['entry']}），不能封禁。"],
            ]);
        }

        if (Fail2Ban::isExempt(Visitor::ip($ip), $request)) {
            throw ValidationException::withMessages(['ip' => ['这个地址被宿主程序豁免，不能封禁。']]);
        }

        $minutes = (int) $minutes;
        $previous = $this->bans->find($key);

        $ban = $this->bans->banManually($key, [
            'incident' => $this->incidents->nextId(),
            'operator' => $actor,
            'note' => $note,
            'ip' => $ip,
            'observe' => $this->settings->all()['mode'] === 'observe',
        ], $minutes);

        // 以这次为准：被覆盖的那次封禁已不存在，它的事件不再显示为「已封禁」。
        if ($previous !== null && $previous['incident'] !== $ban['incident']) {
            rescue(fn () => $this->incidents->markUnbanned($previous['incident']));
        }

        // 写攻击事件失败时，事件里带的是未经存储规范化的同一组字段（与自动封禁一致）。
        $incident = ['id' => $ban['incident'], 'disposition' => 'banned', 'time' => $ban['banned_at']] + $ban;
        $incident = rescue(fn () => $this->incidents->record($incident), $incident);

        rescue(fn () => $this->stats->incrementBans());
        rescue(fn () => $this->events->dispatch(new IpBanned($ban, $incident, $via)));

        $this->record($actor, $via, 'ban', $key, "封 {$minutes} 分钟。备注：".($note ?? '无'), [
            'incident' => $ban['incident'],
            'minutes' => $minutes,
            'note' => $note,
            'replaced' => $previous['incident'] ?? null,
        ]);

        return $ban;
    }

    /**
     * 添加白名单条目：同时解封所有落在这个条目里的当前封禁（每个发一次 IpUnbanned，原因 allowlisted），写操作日志。
     *
     * @return array{entry: string, note: ?string, added_by: string, added_at: int} 添加的条目
     *
     * @throws \Illuminate\Validation\ValidationException 错误键 entry、note
     */
    public function allow(string $entry, ?string $note, string $actor, string $via): array
    {
        $note = is_string($note) && trim($note) !== '' ? trim($note) : null;

        Validator::make(compact('entry', 'note'), [
            'entry' => ['required', 'string'],
            'note' => ['nullable', 'string', 'max:'.self::NOTE_MAX],
        ], [
            'entry.required' => '请填写 IP 或网段。',
            'note.max' => '备注最多 '.self::NOTE_MAX.' 个字。',
        ])->validate();

        $record = $this->allowlist->add($entry, $note, $actor);

        $unbanned = [];

        rescue(function () use ($record, $actor, $via, &$unbanned) {
            foreach ($this->bans->all() as $ban) {
                if (Visitor::covers($record['entry'], $ban['visitor'])) {
                    $this->release($ban['visitor'], $actor, $via, "加入白名单 {$record['entry']}，自动解除", IpUnbanned::REASON_ALLOWLISTED);
                    $unbanned[] = $ban['visitor'];
                }
            }
        });

        $text = '加入白名单，备注：'.($note ?? '无');

        if ($unbanned !== []) {
            $text .= '。同时解封 '.count($unbanned).' 个访客：'.implode('、', $unbanned);
        }

        $this->record($actor, $via, 'allow_add', $record['entry'], $text, ['note' => $note, 'unbanned' => $unbanned]);

        return $record;
    }

    /**
     * 删除白名单条目。条目不存在时什么都不做，返回 false，不写日志。
     */
    public function disallow(string $entry, string $actor, string $via): bool
    {
        $entry = trim($entry);

        if (! $this->allowlist->remove($entry)) {
            return false;
        }

        $this->record($actor, $via, 'allow_remove', $entry, '移出白名单');

        return true;
    }

    /**
     * 保存设置：校验与保存都交给 SettingsRepository（唯一一处实现），
     * 任何一项不合法整体拒绝、原值不变。成功后写带旧值与新值的操作日志：
     * 运行模式的变化记一条 mode，其余的变化合成一条 settings；都没变化时也记一条。
     *
     * 运行模式从别的模式切到拦截时，解除名单里观察期间产生的自动封禁（见 clearObservationBans()），
     * 并在这次的 mode 操作日志里写明解除了几个。面板与命令行都走这里。
     *
     * @param  array  $changes  存储形状的改动（见 SettingsRepository）
     * @return array 保存后的设置（存储形状）
     *
     * @throws \Illuminate\Validation\ValidationException 错误键是存储的点号路径
     */
    public function saveSettings(array $changes, string $actor, string $via): array
    {
        $before = $this->settings->all();
        $after = $this->settings->save($changes, $actor);

        $old = Arr::dot(Arr::except($before, ['updated_by', 'updated_at']));
        $new = Arr::dot(Arr::except($after, ['updated_by', 'updated_at']));

        $changed = array_keys(array_filter($new, fn ($value, $field) => ($old[$field] ?? null) !== $value, ARRAY_FILTER_USE_BOTH));

        if ($changed === []) {
            array_keys($changes) === ['mode']
                ? $this->record($actor, $via, 'mode', '运行模式', '仍为「'.$this->modeLabel($after['mode']).'」，没有改动', ['old' => $before['mode'], 'new' => $after['mode']])
                : $this->record($actor, $via, 'settings', '防护配置', '保存了防护配置，没有改动', ['old' => [], 'new' => []]);

            return $after;
        }

        if (in_array('mode', $changed, true)) {
            $cleared = $after['mode'] === 'block' ? rescue(fn () => $this->clearObservationBans($actor, $via), false) : null;

            $this->recordMode($actor, $via, $before['mode'], $after['mode'], $cleared);
        }

        if ($fields = array_values(array_diff($changed, ['mode']))) {
            $this->record($actor, $via, 'settings', $this->targets($fields),
                implode('；', array_map(fn ($field) => $this->describe($field, $old[$field] ?? null, $new[$field]), $fields)),
                ['old' => Arr::only($old, $fields), 'new' => Arr::only($new, $fields)],
            );
        }

        return $after;
    }

    /**
     * 切换运行模式：就是只改 mode 的保存设置。
     *
     * @throws \Illuminate\Validation\ValidationException 错误键 mode
     */
    public function switchMode(string $mode, string $actor, string $via): array
    {
        return $this->saveSettings(['mode' => $mode], $actor, $via);
    }

    /**
     * 解除名单里观察期间产生的自动封禁，返回解除了几个。
     *
     * 新规则：观察模式只记录、不拦截，它产生的封禁不能在切到拦截的那一刻突然生效（那样就绕开了
     * 「先观察几天再拦截」）。所以切到拦截时，标着观察（observe）的自动封禁全部解除：攻击事件保留，
     * 处置照解封的口径变为「已解封」。手动封禁是运维当面做的决定，即使发生在观察期间也保留。
     * 解除走 BanRepository::unban()，与面板解封相同（会一并清掉这个访客的命中记录与累犯记录）。
     * 每解除一个发一次 IpUnbanned（原因 observation_cleared）。
     */
    protected function clearObservationBans(string $actor, string $via): int
    {
        $cleared = 0;

        foreach ($this->bans->all() as $ban) {
            if (! $ban['observe'] || $ban['source'] !== 'auto') {
                continue;
            }

            if (($removed = $this->bans->unban($ban['visitor'])) !== null) {
                rescue(fn () => $this->incidents->markUnbanned($removed['incident']));
                rescue(fn () => $this->events->dispatch(new IpUnbanned($ban['visitor'], $removed, $actor, $via, IpUnbanned::REASON_OBSERVATION_CLEARED)));
                $cleared++;
            }
        }

        return $cleared;
    }

    /**
     * 写一条操作日志；detail 是 {text, ...附加的结构化内容}。
     *
     * 总是在改动之后调用：写失败只上报，不让已经生效的改动报成失败。
     */
    protected function record(string $actor, string $via, string $action, string $target, string $text, array $extra = []): void
    {
        rescue(fn () => $this->audit->record($actor, $action, $target, ['text' => $text] + $extra, $via));
    }

    /**
     * 运行模式改了：一条 mode 操作日志。
     *
     * @param  int|false|null  $cleared  切到拦截时解除的观察期封禁个数；false 表示解除时出错；null 表示不是切到拦截
     */
    protected function recordMode(string $actor, string $via, string $old, string $new, int|false|null $cleared): void
    {
        $text = '由「'.$this->modeLabel($old).'」改为「'.$this->modeLabel($new).'」';

        $extra = ['old' => $old, 'new' => $new];

        if ($cleared !== null) {
            $text .= $cleared === false
                ? '，解除观察期间产生的自动封禁时出错，请到封禁列表核对'
                : "，同时解除观察期间产生的 {$cleared} 个自动封禁";
            $extra['cleared'] = $cleared === false ? null : $cleared;
        }

        $this->record($actor, $via, 'mode', '运行模式', $text, $extra);
    }

    /**
     * 访客键；不合法时抛 422。
     */
    protected function visitorKey(string $ip, string $field): string
    {
        try {
            return Visitor::key($ip);
        } catch (InvalidArgumentException) {
            throw ValidationException::withMessages([$field => ['不是合法的 IP 地址或访客键。']]);
        }
    }

    /**
     * 改动涉及的对象：规则名、累犯加长、拦截响应。
     */
    protected function targets(array $fields): string
    {
        $targets = [];

        foreach ($fields as $field) {
            $parts = explode('.', $field);

            $targets[] = match ($parts[0]) {
                'rules' => $this->ruleName($parts[1]),
                'repeat' => '累犯加长',
                'response' => '拦截响应',
                default => $parts[0],
            };
        }

        return implode('、', array_unique($targets));
    }

    /**
     * 一项改动的说明，例如「404 扫描 封禁时长由 10 分钟改为 30 分钟」：
     * 可选值与开关写成「…」，紧挨前后文字；数字前后留空格，带单位时单位后不留。
     */
    protected function describe(string $field, mixed $old, mixed $new): string
    {
        if ($field === 'response.message') {
            return '提示文字已修改';
        }

        $parts = explode('.', $field);

        [$label, $format] = match (true) {
            $parts[0] === 'rules' => [
                $this->ruleName($parts[1]).' '.(['action' => '动作', 'window' => '时间范围', 'count' => '出现次数', 'ban' => '封禁时长'][$parts[2]] ?? $parts[2]),
                match ($parts[2]) {
                    'action' => fn ($v) => '「'.(self::ACTION_LABELS[$v] ?? $v).'」',
                    'window', 'ban' => fn ($v) => " {$v} 分钟",
                    default => fn ($v) => " {$v} ",
                },
            ],
            is_bool($new) => [self::FIELD_LABELS[$field] ?? $field, fn ($v) => $v ? '「开」' : '「关」'],
            in_array($field, ['repeat.max_days', 'repeat.keep_days'], true) => [self::FIELD_LABELS[$field], fn ($v) => " {$v} 天"],
            default => [self::FIELD_LABELS[$field] ?? $field, fn ($v) => " {$v} "],
        };

        return rtrim("{$label}由{$format($old)}改为{$format($new)}");
    }

    protected function modeLabel(string $mode): string
    {
        return self::MODE_LABELS[$mode] ?? $mode;
    }

    /**
     * 设置里的规则就是配置 fail2ban.rules 的键，规则入口按同一份配置构建，每条都在。
     */
    protected function ruleName(string $id): string
    {
        return $this->inspector->rule($id)->name();
    }
}
