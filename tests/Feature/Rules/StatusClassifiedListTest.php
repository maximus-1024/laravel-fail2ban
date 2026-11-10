<?php

namespace Maximus\Fail2Ban\Tests\Feature\Rules;

use InvalidArgumentException;
use Maximus\Fail2Ban\Rules\KnownExploit;
use Maximus\Fail2Ban\Rules\SensitivePath;
use Maximus\Fail2Ban\Rules\Support\CompiledLists;
use Maximus\Fail2Ban\Rules\Support\PatternList;
use Maximus\Fail2Ban\Rules\Support\Subject;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

/**
 * 地址清单按分段标题上的状态标记分两类（PatternList::parseByStatus()），每类配一条预筛正则
 * （PatternList::gate()、Subject::pathMayMatch()）。
 */
class StatusClassifiedListTest extends RuleTestCase
{
    /**
     * @var list<string>
     */
    private array $files = [];

    protected function tearDown(): void
    {
        foreach ($this->files as $file) {
            @unlink($file);
        }

        parent::tearDown();
    }

    private function listFile(string $content): string
    {
        $this->files[] = $file = tempnam(sys_get_temp_dir(), 'fail2ban-list-');
        file_put_contents($file, $content);

        return $file;
    }

    // ---------------------------------------------------------------- 标记的解析

    #[Test]
    public function heading_markers_split_entries_into_two_classes(): void
    {
        $file = $this->listFile(implode("\n", [
            '# 注释',
            '/before-any-heading',
            '## 第一段 [any-status]',
            '*.env',
            '# 段内注释 [non-success]',
            '*/.git/*',
            '## 第二段 [non-success]',
            '/horizon/*',
            '## 没有标记的段',
            '/untagged',
            '## 又一段 [any-status]  ',
            '*.sql',
            '##不是标题，是注释 [non-success]',
            '*.bak',
        ]));

        $this->assertSame([
            PatternList::ANY_STATUS => ['*.env', '*/.git/*', '*.sql', '*.bak'],
            PatternList::NON_SUCCESS => ['/before-any-heading', '/horizon/*', '/untagged'],
        ], PatternList::parseByStatus($file));

        // 不分类的解析照旧：全部条目，按文件顺序
        $this->assertSame(
            ['/before-any-heading', '*.env', '*/.git/*', '/horizon/*', '/untagged', '*.sql', '*.bak'],
            PatternList::parse($file),
        );
    }

    #[Test]
    public function a_list_without_markers_is_all_non_success(): void
    {
        $file = $this->listFile("## 老格式\n*.env\n## 另一段\n/horizon/*\n");

        $this->assertSame([PatternList::ANY_STATUS => [], PatternList::NON_SUCCESS => ['*.env', '/horizon/*']], PatternList::parseByStatus($file));
    }

    #[Test]
    public function a_misspelled_marker_is_rejected(): void
    {
        $this->expectException(InvalidArgumentException::class);

        PatternList::parseByStatus($this->listFile("## 环境文件 [any]\n*.env\n"));
    }

    #[Test]
    public function bundled_lists_are_classified_as_documented(): void
    {
        $sensitive = SensitivePath::builtinEntries();
        $exploit = KnownExploit::builtinEntries();
        $paths = fn (array $entries) => array_values(array_filter($entries, fn (string $entry) => $entry[0] !== '?'));

        $this->assertCount(174, $sensitive[PatternList::ANY_STATUS]);
        $this->assertCount(132, $sensitive[PatternList::NON_SUCCESS]);
        $this->assertCount(17, $paths($exploit[PatternList::ANY_STATUS]));
        $this->assertCount(15, array_filter([...$exploit[PatternList::ANY_STATUS], ...$exploit[PatternList::NON_SUCCESS]], fn (string $entry) => $entry[0] === '?'));
        $this->assertSame(['*/laravel-filemanager/download*', '*/voyager-assets*'], $exploit[PatternList::NON_SUCCESS]);

        // 抽查归属
        foreach (['*/.env*', '*/.git/*', '*.sql', '*.php', '*/storage/logs/*', '*/storage/framework/*', '/artisan', '*/.git-credentials', '*/.kube/*', '*/@fs/*'] as $entry) {
            $this->assertContains($entry, $sensitive[PatternList::ANY_STATUS], $entry);
        }

        foreach (['*/phpmyadmin*', '*/wp-*', '/horizon/*', '/telescope/*', '*/_profiler/*', '/nova/*', '/laravel-filemanager/*', '*/gponform/*', '*/env.js', '*/env.json', '/livewire/*', '*/credentials.json'] as $entry) {
            $this->assertContains(strtolower($entry), array_map(strtolower(...), $sensitive[PatternList::NON_SUCCESS]), $entry);
        }

        // 2026-11-10 起任何层级都算，只在根目录的条目只剩这 8 条（普通英文词，或包把前端文件发布在 public/vendor 下，见清单里的说明）
        $rootOnly = array_values(array_filter([...$sensitive[PatternList::ANY_STATUS], ...$sensitive[PatternList::NON_SUCCESS]], fn (string $entry) => $entry[0] === '/'));
        $this->assertSame(['/artisan', '/telescope/*', '/horizon/*', '/pulse/*', '/log-viewer/*', '/nova/*', '/laravel-filemanager/*', '/livewire/*'], $rootOnly);
    }

    #[Test]
    public function customizing_by_status(): void
    {
        $lists = [PatternList::ANY_STATUS => ['*.env', '*.sql'], PatternList::NON_SUCCESS => ['/horizon/*', '/nova/*']];

        $this->assertSame([
            PatternList::ANY_STATUS => ['*.env', '/mine-any'],
            PatternList::NON_SUCCESS => ['/horizon/*', '/mine'],
        ], PatternList::customizeByStatus($lists, ['/mine', ' ', '# 注释'], ['/mine-any'], ['*.SQL', '/NOVA/*']));
    }

    // ---------------------------------------------------------------- 预筛

    /**
     * 两条地址清单规则的编译产物，每条两类：[规则, 正则键, 预筛键]。
     *
     * @return list<array{string, string, string}>
     */
    private static function classes(): array
    {
        return [
            [SensitivePath::class, 'any', 'any_gate'],
            [SensitivePath::class, 'non_success', 'non_success_gate'],
            [KnownExploit::class, 'any', 'any_gate'],
            [KnownExploit::class, 'non_success', 'non_success_gate'],
        ];
    }

    /**
     * 两份地址清单里每个路径条目造一个地址，再加上会经过解码、清理、归一化的各种写法。
     */
    public static function listSamples(): array
    {
        $samples = [];

        foreach (glob(dirname(__DIR__, 3).'/resources/rules/*-paths.txt') as $file) {
            foreach (PatternList::parse($file) as $entry) {
                if ($entry[0] === '?') {
                    continue;
                }

                $core = trim($entry, '*');
                $uri = (str_starts_with($entry, '*') ? '/p' : '').(str_starts_with($core, '/') || str_starts_with($entry, '*') ? '' : '/').$core.(str_ends_with($entry, '*') ? 'z' : '');
                $samples[$entry] = [$uri];
            }
        }

        return $samples;
    }

    /**
     * 一个地址的各种写法：每种都对应预筛里的一个正确性边界（大小写、补斜杠、"//"、"%"、反斜杠、空字节、开头没有斜杠）。
     *
     * @return list<string>
     */
    private static function variants(string $uri): array
    {
        $rest = ltrim($uri, '/');

        // 开头的斜杠保留不动，免得被「开头不是斜杠」那一条顺带兜住，测不到后面几条边界
        return [
            $uri,
            strtoupper($uri),
            rtrim($uri, '/z'),
            $uri.'/',
            str_replace('/', '//', $uri),
            '/'.str_replace('/', '%2F', $rest),
            '/'.sprintf('%%%02X', ord($rest[0])).substr($rest, 1),
            '/'.sprintf('%%25%02X', ord($rest[0])).substr($rest, 1),
            '/'.str_replace('/', '\\', $rest),
            '/'.substr($rest, 0, 2)."\0".substr($rest, 2),
            $rest,
        ];
    }

    #[Test]
    #[DataProvider('listSamples')]
    public function the_gate_never_hides_a_match(string $uri): void
    {
        foreach (self::classes() as [$class, $regex, $gate]) {
            $compiled = CompiledLists::for($class);

            foreach (self::variants($uri) as $variant) {
                $subject = Subject::of($this->makeRequest('GET', $variant));

                if (PatternList::test($compiled[$regex], $subject->pathCandidates())) {
                    $this->assertTrue($subject->pathMayMatch($compiled[$gate][0]), "$class $regex ".json_encode($variant));
                }
            }
        }
    }

    #[Test]
    public function the_gate_never_hides_a_match_for_host_entries_without_dots(): void
    {
        // 宿主追加的条目也一样：现编的预筛正则覆盖不带预筛字符的条目
        $entries = ['/internal-backup/*', '*_secret', '/exact', '*/deep/path/*', 'prefix-only*', '*suffix-only'];
        $regex = PatternList::regex($entries);
        $gate = PatternList::gate($entries);

        foreach (['/internal-backup/x', '/a/b_secret', '/exact', '/x/deep/path', '/prefix-onlyx', '/x/suffix-only'] as $uri) {
            foreach (self::variants($uri) as $variant) {
                $subject = Subject::of($this->makeRequest('GET', $variant));

                if (PatternList::test($regex, $subject->pathCandidates())) {
                    $this->assertTrue($subject->pathMayMatch($gate), json_encode($variant));
                }
            }

            $this->assertTrue(Subject::of($this->makeRequest('GET', $uri))->pathMayMatch($gate), $uri);
        }
    }

    public static function ordinaryPaths(): array
    {
        return [
            ['/'], ['/v1/transactions/pay'], ['/v1/transactions/pay/'], ['/v1/transactions/payout/query'],
            ['/v1/prepay/4442ed3ed642f7308babe09b9007675ed487e0309a82d'], ['/merchant/deposit-orders/12345/notify'],
            ['/merchant/merchants/me'], ['/merchant/auth/login'], ['/merchant/common/downloads/withdrawals/import-template'],
            ['/portal/api/deposit-orders/12/transactions/reconcile-preview'], ['/agent/commissions/export'],
            ['/fail2ban'], ['/fail2ban/api/bans'], ['/storage/images/logo'], ['/horizontal'], ['/api/v2/orders/7'],
        ];
    }

    /**
     * 正常接口路径在预筛这一步就结束：不解码、不跑完整清单（每个请求都要看「任意状态」组，靠这一步不拖慢）。
     */
    #[Test]
    #[DataProvider('ordinaryPaths')]
    public function ordinary_paths_stop_at_the_gate(string $path): void
    {
        foreach (self::classes() as [$class, , $gate]) {
            $this->assertFalse(Subject::of($this->makeRequest('GET', $path))->pathMayMatch(CompiledLists::for($class)[$gate][0]), "$class $gate $path");
        }
    }
}
