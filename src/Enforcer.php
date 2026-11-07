<?php

namespace Maximus\Fail2Ban;

use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Maximus\Fail2Ban\Contracts\AllowlistRepository;
use Maximus\Fail2Ban\Contracts\BanRepository;
use Maximus\Fail2Ban\Contracts\IncidentRepository;
use Maximus\Fail2Ban\Contracts\StatsRepository;
use Maximus\Fail2Ban\Events\BanSkipped;
use Maximus\Fail2Ban\Events\IpBanned;
use Maximus\Fail2Ban\Support\Text;

/**
 * 收尾阶段的封禁流程：中间件确认本次请求有规则命中之后才用到它。
 *
 *     白名单 → 记命中与统计 → 达到出现次数？
 *         规则动作为观察：恰好达到时写一条「仅记录」事件
 *         规则动作为封禁：宿主豁免 → 恰好达到时写「已豁免」事件并发 BanSkipped
 *                         不豁免   → 自动封禁；真的封上了才写事件、计封禁数、发 IpBanned
 *
 * 不持有任何请求相关的状态，可以安全地作为单例或在常驻进程里复用。
 *
 * 日志一律经 Log 门面写（宿主的 log 绑定不一定实现 Psr\Log\LoggerInterface，不按这个接口注入）。
 *
 * 封禁写进 Redis 之后的几步（写攻击事件、计封禁数、发出事件）各自兜住异常（rescue()，经宿主的
 * 异常处理上报）：一次读超时不会把后面几步全部带掉，事件的派发也不依赖前面几步都成功。
 */
class Enforcer
{
    /**
     * Create a new enforcer instance.
     */
    public function __construct(
        protected BanRepository $bans,
        protected AllowlistRepository $allowlist,
        protected IncidentRepository $incidents,
        protected StatsRepository $stats,
        protected Dispatcher $events,
    ) {
    }

    /**
     * 一个已被封访客的请求被拦下（或观察模式下本应被拦）：被拦次数加一，本小时拦截数加一。
     */
    public function blocked(string $visitor): void
    {
        $this->bans->recordBlock($visitor);
        $this->stats->incrementBlocked();
    }

    /**
     * 处理本次请求的规则命中。
     *
     * @param  string  $visitor  访客键
     * @param  non-empty-list<\Maximus\Fail2Ban\RuleHit>  $hits  Inspector::inspect() 的结果
     * @param  array  $settings  进入时读到的运行设置（SettingsRepository::all() 的形状）
     */
    public function handle(Request $request, string $visitor, array $hits, array $settings): void
    {
        $ip = (string) $request->ip();

        if ($this->allowed($ip)) {
            return;
        }

        $context = [
            'visitor' => $visitor,
            'ip' => $ip,
            'region' => $this->region($request),
            'user_agent' => $request->userAgent(), // 存储层截断
            'observe' => ($settings['mode'] ?? null) === 'observe',
        ];

        $reached = $this->record($request, $hits, $settings, $context);

        $exempt = null;
        $banAttempted = false;

        foreach ($reached as [$hit, $rule, $result]) {
            // 恰好达到：这次是新增，且条数正好等于出现次数。一个时间范围里只有一次。
            // 已知限制（有意不处理）：时间范围中途把出现次数调低到已有条数以下，这个时间范围里
            // 不会再出现「恰好等于」，「仅记录」「已豁免」事件要等下一个时间范围才恢复；封禁不受影响（看的是 >=）。
            $exactly = $result['added'] && $result['count'] === (int) $rule['count'];

            if ($rule['action'] === 'observe') {
                if ($exactly) {
                    $this->recordIncident('recorded', $hit, $result, $context);
                }

                continue;
            }

            if ($rule['action'] !== 'ban' || $banAttempted) {
                continue;
            }

            if ($exempt ??= Fail2Ban::isExempt(Visitor::ip($ip), $request)) {
                if ($exactly) {
                    $incident = $this->recordIncident('exempted', $hit, $result, $context);

                    rescue(fn () => $this->events->dispatch(new BanSkipped($incident)));
                }

                continue;
            }

            // 只试一次：封上了，或者已经被封（返回 null），后面的规则都不必再试。
            $banAttempted = true;

            $this->ban($hit, $rule, $settings['repeat'], $context);
        }
    }

    /**
     * 访客在白名单里时不记命中、不封禁。
     */
    protected function allowed(string $ip): bool
    {
        $match = $this->allowlist->match($ip);

        if ($match === null) {
            return false;
        }

        // 落在内置段（内网段、回环、Cloudflare 段）里，说明程序取到的多半不是真实访客（代理、负载均衡、CDN）。
        if (array_key_exists($match['source'], (array) config('fail2ban.allowlist.builtin'))) {
            Log::warning('fail2ban: 命中规则的访客地址落在内置白名单段里，程序取到的可能不是真实访客，请检查 TrustProxies 与代理配置。', [
                'ip' => $ip,
                'entry' => $match['entry'],
                'source' => $match['source'],
            ]);
        }

        return true;
    }

    /**
     * 逐条记入命中与统计，返回达到出现次数的那些。
     *
     * 先把这次的命中全部记完再判断封禁（一次往返记完，见 BanRepository::recordHits()）：封禁会清空各规则的命中记录，
     * 先记完才不会在封禁之后又留下新的命中，攻击者信息里「其它规则的命中次数」也才完整。
     *
     * @param  list<\Maximus\Fail2Ban\RuleHit>  $hits
     * @return list<array{0: \Maximus\Fail2Ban\RuleHit, 1: array, 2: array{count: int, added: bool}}>
     */
    protected function record(Request $request, array $hits, array $settings, array $context): array
    {
        // 全部命中连同命中统计一次往返。命中的规则都在设置里：规则入口只检测设置里动作为检测的规则。
        $results = $this->bans->recordHits(
            $context['visitor'],
            array_map(fn (RuleHit $hit) => [
                'rule' => $hit->rule,
                'dedupe' => $hit->key,
                'record' => $hit->record(),
                'window' => (int) $settings['rules'][$hit->rule]['window'],
            ], $hits),
            max(1, (int) config('fail2ban.hits_max', 100)),
            $this->target($request),
            $context['region'],
        );

        $reached = [];

        foreach ($hits as $i => $hit) {
            $rule = $settings['rules'][$hit->rule];

            if ($results[$i]['count'] >= (int) $rule['count']) {
                $reached[] = [$hit, $rule, $results[$i]];
            }
        }

        return $reached;
    }

    /**
     * 自动封禁。存储层返回 null 说明已经被封，什么都不再做。
     */
    protected function ban(RuleHit $hit, array $rule, array $repeat, array $context): void
    {
        $ban = $this->bans->ban($context['visitor'], [
            'incident' => $this->incidents->nextId(),
            'rule' => $hit->rule,
            'ip' => $context['ip'],
            'region' => $context['region'],
            'user_agent' => $context['user_agent'],
            'observe' => $context['observe'],
        ], (int) $rule['ban'], $repeat);

        if ($ban === null) {
            return;
        }

        // 封禁已经生效：后面每一步各自兜住异常。写攻击事件失败时，事件里带的是未经存储规范化的同一组字段。
        $incident = ['id' => $ban['incident'], 'disposition' => 'banned', 'time' => $ban['banned_at']] + $ban;
        $incident = rescue(fn () => $this->incidents->record($incident), $incident);

        rescue(fn () => $this->stats->incrementBans());

        rescue(fn () => $this->events->dispatch(new IpBanned($ban, $incident)));
    }

    /**
     * 写一条没有封禁的攻击事件：「仅记录」或「已豁免」。附上触发规则的命中记录与其它规则的条数。
     * 读命中记录、写事件各自兜住异常，返回的总是一条事件（写失败时是未写进历史的那组字段）。
     *
     * @param  'recorded'|'exempted'  $disposition
     * @param  array{count: int, added: bool}  $result
     */
    protected function recordIncident(string $disposition, RuleHit $hit, array $result, array $context): array
    {
        $hits = rescue(fn () => $this->bans->hits($context['visitor']), []);
        $requests = $hits[$hit->rule] ?? [];
        unset($hits[$hit->rule]);

        $incident = [
            'id' => $this->incidents->nextId(),
            'time' => now()->getTimestamp(),
            'disposition' => $disposition,
            'visitor' => $context['visitor'],
            'ip' => $context['ip'],
            'region' => $context['region'],
            'rule' => $hit->rule,
            'source' => 'auto',
            'count' => $result['count'],
            'observe' => $context['observe'],
            'user_agent' => $context['user_agent'],
            'first_hit_at' => $requests[0]['time'] ?? null,
            'other_rules' => array_map('count', $hits),
            'requests' => $requests,
        ];

        // 写失败时返回未经存储规范化的同一组字段，调用方照样能发出事件。
        return rescue(fn () => $this->incidents->record($incident), $incident);
    }

    /**
     * 攻击目标：请求路径（原样，不含查询参数），按 PATH_MAX 截断。
     */
    protected function target(Request $request): string
    {
        return Text::path($request->getPathInfo());
    }

    /**
     * 来源地区：取配置的请求头（默认 Cloudflare 的 CF-IPCountry），没有就是 null。
     */
    protected function region(Request $request): ?string
    {
        $header = config('fail2ban.region_header');

        if (! is_string($header) || $header === '') {
            return null;
        }

        $value = trim((string) $request->headers->get($header, ''));

        return $value === '' ? null : Text::clip($value, 32);
    }
}
