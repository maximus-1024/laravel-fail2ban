<?php

namespace Maximus\Fail2Ban\Tests\Feature\Rules;

use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\Test;
use RuntimeException;

/**
 * 规则检测在 php-fpm 条件下近乎零成本——每个请求都是全新的进程状态，但 opcache 是热的。
 *
 * 在单独的子进程里跑 tests/Support/rules-benchmark.php（带 -d opcache.enable_cli=1：CLI 默认不开
 * opcache，而且这个设置不能在运行时打开）。它在每次测量之前清空本包所有类的静态属性、重建规则入口、
 * 新建请求对象，计时包含「建规则入口 + 检测」。四组请求：正常、带查询串的正常、404、扫描。
 *
 * 防退化上限取 2026-11-07 实测中位数与 p95 的十倍左右（WSL2 上的 docker，PHP 8.4，见汇报）。
 * 注意：正常请求的十倍上限（80 微秒）比改动前的实测（约 42 微秒）还宽，回到「每个请求解析清单」
 * 靠这里拦不住；那一条由 CompiledListsTest 的确定性断言保证（不配追加、排除时规则只用编译产物）。
 */
#[Group('benchmark')]
class RulesPerRequestBenchmarkTest extends RuleTestCase
{
    /**
     * 每组的上限（微秒）：[中位数, p95]。
     */
    private const LIMITS = [
        'normal' => [80, 150],
        'normal_query' => [100, 200],
        'not_found' => [200, 400],
        'scan' => [200, 500],
    ];

    #[Test]
    public function detection_is_nearly_free_when_every_request_starts_from_a_fresh_process_state(): void
    {
        $result = $this->runBenchmark('--samples=1000');

        $this->assertTrue($result['opcache'], '子进程里 opcache 没有生效');
        $this->assertTrue($result['compiled_cached'], '编译产物没有进 opcache');
        $this->report('per request, opcache on', $result);

        foreach (self::LIMITS as $group => [$median, $p95]) {
            $this->assertLessThan($median, $result['groups'][$group]['total']['median'], "{$group} 中位数");
            $this->assertLessThan($p95, $result['groups'][$group]['total']['p95'], "{$group} p95");
        }

        $this->assertSame(0, $result['groups']['normal']['hits'], '正常请求不应命中');
        $this->assertSame(0, $result['groups']['normal_query']['hits'], '正常请求不应命中');
        $this->assertSame($result['groups']['not_found']['n'], $result['groups']['not_found']['hits'], '每个 404 只命中 404 扫描');
        $this->assertGreaterThanOrEqual($result['groups']['scan']['n'], $result['groups']['scan']['hits'], '每个扫描请求至少命中一条');
    }

    /**
     * @return array{opcache: bool, compiled_cached: bool, customized: bool, groups: array<string, array{n: int, hits: int, build: array{median: float, p95: float}, total: array{median: float, p95: float}}>}
     */
    private function runBenchmark(string ...$arguments): array
    {
        $command = [
            PHP_BINARY, '-d', 'opcache.enable_cli=1', '-d', 'opcache.file_update_protection=0',
            dirname(__DIR__, 2).'/Support/rules-benchmark.php', ...$arguments,
        ];

        $process = proc_open($command, [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
        $output = stream_get_contents($pipes[1]);
        $errors = stream_get_contents($pipes[2]);
        $status = proc_close($process);

        $result = json_decode((string) $output, true);

        if ($status !== 0 || ! is_array($result)) {
            throw new RuntimeException("rules-benchmark.php failed ({$status}): {$errors}{$output}");
        }

        return $result;
    }

    private function report(string $label, array $result): void
    {
        foreach ($result['groups'] as $group => $r) {
            fwrite(STDERR, sprintf(
                "[rules benchmark, %s] %-12s n=%d 中位数 %.1fµs p95 %.1fµs（其中建规则入口 中位数 %.1fµs）命中 %d\n",
                $label, $group, $r['n'], $r['total']['median'], $r['total']['p95'], $r['build']['median'], $r['hits'],
            ));
        }
    }
}
