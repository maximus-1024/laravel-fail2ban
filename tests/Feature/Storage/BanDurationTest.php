<?php

namespace Maximus\Fail2Ban\Tests\Feature\Storage;

use Maximus\Fail2Ban\BanDuration;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * 时长计算部分（纯函数）。生产代码只有时长表 BanDuration::schedule()，封禁脚本按已封次数查表；
 * 这里用可读写法 minutes() 作对照。
 */
class BanDurationTest extends TestCase
{
    private const REPEAT = ['enabled' => true, 'factor' => 2, 'max_days' => 7, 'keep_days' => 7];

    /**
     * 可读写法：RULE_BAN × REPEAT_FACTOR ^ 已封次数，不超过 REPEAT_MAX；RULE_BAN 本身更长时按 RULE_BAN。
     */
    private static function minutes(int $ruleBan, int $previous, array $repeat): int
    {
        if (! $repeat['enabled'] || $previous === 0) {
            return $ruleBan;
        }

        $cap = $repeat['max_days'] * 1440;

        return $ruleBan >= $cap ? $ruleBan : (int) min($ruleBan * $repeat['factor'] ** $previous, $cap);
    }

    /**
     * 生产的取法（与封禁脚本相同）：时长表的第「已封次数」项，超出取最后一项。
     */
    private static function lookup(int $ruleBan, int $previous, array $repeat): int
    {
        $schedule = BanDuration::schedule($ruleBan, $repeat);

        return $schedule[min($previous, count($schedule) - 1)];
    }

    #[Test]
    public function first_ban_uses_the_rule_ban(): void
    {
        $this->assertSame(30, self::lookup(30, 0, self::REPEAT));
    }

    #[Test]
    public function each_previous_ban_multiplies_by_the_factor(): void
    {
        // 404 扫描依次是 30 分钟、1 小时、2 小时、4 小时……
        $this->assertSame([30, 60, 120, 240, 480], array_map(
            fn ($previous) => self::lookup(30, $previous, self::REPEAT), [0, 1, 2, 3, 4]
        ));

        $this->assertSame(270, self::lookup(30, 2, ['factor' => 3] + self::REPEAT));
    }

    #[Test]
    public function the_result_is_capped_at_repeat_max(): void
    {
        $this->assertSame(7 * 1440, self::lookup(30, 9, self::REPEAT));   // 30 × 512 = 15360 > 10080
        $this->assertSame(7 * 1440, self::lookup(30, 500, self::REPEAT)); // 不溢出
        $this->assertSame(1440, self::lookup(120, 5, ['max_days' => 1] + self::REPEAT));
    }

    #[Test]
    public function a_rule_ban_longer_than_the_cap_is_kept(): void
    {
        $this->assertSame([20000], BanDuration::schedule(20000, self::REPEAT));
        $this->assertSame(20000, self::lookup(20000, 3, self::REPEAT));
    }

    #[Test]
    public function disabled_repeat_always_uses_the_rule_ban(): void
    {
        $this->assertSame([30], BanDuration::schedule(30, ['enabled' => false] + self::REPEAT));
    }

    #[Test]
    public function the_schedule_agrees_with_the_readable_formula(): void
    {
        foreach ([1, 7, 30, 120, 1439, 1440, 43200] as $ruleBan) {
            foreach ([2, 3, 10] as $factor) {
                foreach ([1, 7, 30] as $maxDays) {
                    foreach ([true, false] as $enabled) {
                        $repeat = ['enabled' => $enabled, 'factor' => $factor, 'max_days' => $maxDays, 'keep_days' => 7];

                        foreach ([0, 1, 2, 5, 20, 500] as $previous) {
                            $this->assertSame(self::minutes($ruleBan, $previous, $repeat), self::lookup($ruleBan, $previous, $repeat), json_encode([$ruleBan, $previous, $repeat]));
                        }
                    }
                }
            }
        }
    }
}
