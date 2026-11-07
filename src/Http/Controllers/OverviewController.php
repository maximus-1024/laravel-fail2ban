<?php

namespace Maximus\Fail2Ban\Http\Controllers;

use Carbon\CarbonImmutable;
use Illuminate\Http\Request;
use Maximus\Fail2Ban\Contracts\BanRepository;
use Maximus\Fail2Ban\Contracts\IncidentRepository;
use Maximus\Fail2Ban\Contracts\SettingsRepository;
use Maximus\Fail2Ban\Contracts\StatsRepository;
use Maximus\Fail2Ban\Http\Presenter;

class OverviewController extends Controller
{
    /**
     * 最多看多少小时（近 7 天）。
     */
    public const MAX_HOURS = 168;

    /**
     * 排行各取多少项。
     */
    public const TOP = 10;

    /**
     * 近期事件条数。
     */
    public const RECENT = 5;

    public function index(
        Request $request,
        StatsRepository $stats,
        BanRepository $bans,
        IncidentRepository $incidents,
        SettingsRepository $settings,
        Presenter $presenter,
    ) {
        $hours = filter_var($request->query('hours', 24), FILTER_VALIDATE_INT);
        $hours = $hours === false ? 24 : min(self::MAX_HOURS, max(1, $hours));

        // 排行按天存：取时间范围实际跨到的那几天（与趋势同一组小时段，最早的从当前小时往前数 hours-1 个小时）。
        // 例如上午十点看近 24 小时，跨了昨天和今天两天；排行是这几天的整天合计。
        $now = CarbonImmutable::now();
        $days = (int) round($now->startOfHour()->subHours($hours - 1)->startOfDay()->diffInDays($now->startOfDay())) + 1;

        $current = $settings->all();
        $trend = collect($stats->trend($hours));
        $active = $bans->all();

        $rules = collect(array_keys($current['rules']))
            ->map(fn (string $id) => $presenter->rule($id) + ['hits' => $trend->sum(fn (array $hour) => $hour['rules'][$id] ?? 0)])
            ->sortByDesc('hits')
            ->values()
            ->all();

        return response()->json([
            'enabled' => (bool) config('fail2ban.enabled'),
            'mode' => $current['mode'],
            'kpis' => [
                'blocked' => $trend->sum('blocked'),
                'new_bans' => $trend->sum('bans'),
                'active_bans' => count($active),
                'repeat_offenders' => count(array_filter($active, fn ($ban) => ($ban['offense'] ?? 0) > 1)),
                'hits' => $trend->sum('hits'),
            ],
            'trend' => $trend->map(fn (array $hour) => [
                'hour' => $presenter->time($hour['hour']),
                'hits' => $hour['hits'],
                'blocked' => $hour['blocked'],
                'bans' => $hour['bans'],
            ])->all(),
            'rules' => $rules,
            'top_ips' => $stats->top('ip', self::TOP, $days),
            'top_targets' => $stats->top('target', self::TOP, $days),
            'top_regions' => $stats->top('region', self::TOP, $days),
            'recent' => array_map(
                fn (array $incident) => $presenter->incident($incident),
                $incidents->paginate([], 1, self::RECENT)['data'],
            ),
        ]);
    }
}
