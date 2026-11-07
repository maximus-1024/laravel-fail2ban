<?php

namespace Maximus\Fail2Ban\Tests\Feature\Panel;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\Test;

/**
 * 总览的三个排行按时间范围实际跨到的日期来取。
 * 排行按天存，所以取的是这些天的整天合计（与时间范围差不到一天）。
 */
class OverviewRankingTest extends PanelTestCase
{
    private function hitAt(string $time, string $visitor, string $target, string $region): void
    {
        $this->travelTo(CarbonImmutable::parse($time));

        $this->recordHit('sensitive-path', $visitor, target: $target, region: $region);
    }

    #[Test]
    public function the_last_24_hours_include_yesterday_evening(): void
    {
        $this->hitAt('2026-11-06 20:00:00', '198.51.100.7', '/.env', 'NL');
        $this->hitAt('2026-11-07 09:00:00', '203.0.113.9', '/.git/config', 'US');

        $this->travelTo(CarbonImmutable::parse('2026-11-07 10:30:00'));
        $json = $this->getJson($this->api('/overview?hours=24'))->assertOk()->json();

        $this->assertEqualsCanonicalizing(['198.51.100.7', '203.0.113.9'], array_column($json['top_ips'], 'key'));
        $this->assertEqualsCanonicalizing(['/.env', '/.git/config'], array_column($json['top_targets'], 'key'));
        $this->assertEqualsCanonicalizing(['NL', 'US'], array_column($json['top_regions'], 'key'));
    }

    #[Test]
    public function a_window_starting_at_midnight_only_reads_today(): void
    {
        $this->hitAt('2026-11-06 20:00:00', '198.51.100.7', '/.env', 'NL');
        $this->hitAt('2026-11-07 09:00:00', '203.0.113.9', '/.git/config', 'US');

        // 23:30 往前 24 个小时段，从今天 00:00 开始
        $this->travelTo(CarbonImmutable::parse('2026-11-07 23:30:00'));

        $this->assertSame(['203.0.113.9'], array_column($this->getJson($this->api('/overview?hours=24'))->json('top_ips'), 'key'));
    }

    #[Test]
    public function the_last_7_days_include_the_eighth_calendar_day(): void
    {
        $this->hitAt('2026-10-31 20:00:00', '198.51.100.7', '/.env', 'NL');
        $this->hitAt('2026-10-30 20:00:00', '192.0.2.1', '/old', 'DE'); // 超出范围

        $this->travelTo(CarbonImmutable::parse('2026-11-07 10:30:00'));

        $this->assertSame(['198.51.100.7'], array_column($this->getJson($this->api('/overview?hours=168'))->json('top_ips'), 'key'));
    }
}
