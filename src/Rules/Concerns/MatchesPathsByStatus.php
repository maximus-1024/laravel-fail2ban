<?php

namespace Maximus\Fail2Ban\Rules\Concerns;

use Maximus\Fail2Ban\Rules\Support\CompiledLists;
use Maximus\Fail2Ban\Rules\Support\PatternList;
use Maximus\Fail2Ban\Rules\Support\Subject;

/**
 * 地址清单规则（敏感文件探测、已知漏洞探测）共用：清单按分段标题上的状态标记分成两类，
 * 各编一条正则（见 PatternList::parseByStatus()）。
 *
 *  - 任意状态（[any-status]）：恶意明确、宿主不会真有的地址（.env、.git、数据库导出、脚本后缀、Laravel 日志、
 *    已知漏洞的利用地址），不看状态码，命中就算。宿主把一切渲染成 HTTP 200 时也照样能抓到。
 *  - 非成功（[non-success]）：宿主可能真有的页面（后台入口、Horizon 等运维面板），响应不是成功
 *    （状态码不在 200–399）时才算：管理员成功打开不算，未授权、不存在、出错都算。
 *
 * 宿主追加的条目默认归「非成功」，写在 extra_any_status 里的归「任意状态」；排除对两类都生效。
 *
 * 性能：以前非 404 的请求直接跳过地址清单，现在每个请求都要看「任意状态」组，401、422、500 等还要看
 * 「非成功」组。每组先做廉价的预筛（Subject::pathMayMatch()：路径里没有 "."、"~"、"%" 等字符时，
 * 只用一条全是字面量的短正则查这一组不带点的条目片段），绝大多数正常接口请求在这里结束，不解码、不跑完整清单。
 * 宿主追加、排除了条目时也一样（见 gates()），完整清单只在预筛通过时才现读现编。
 */
trait MatchesPathsByStatus
{
    use UsesPatternList;

    /**
     * 两类的预筛正则（见 gates()），第一次用到时取得。
     *
     * @var array{any_gate: list<string>, non_success_gate: list<string>}|null
     */
    protected ?array $gates = null;

    /**
     * 内置清单文件里的条目，按状态分两类。
     *
     * @return array{any-status: list<string>, non-success: list<string>}
     */
    public static function builtinEntries(): array
    {
        return PatternList::parseByStatus(static::file());
    }

    /**
     * @param  array{any-status: list<string>, non-success: list<string>}  $builtin
     * @return array{any-status: list<string>, non-success: list<string>}
     */
    protected static function customizeEntries(array $builtin, array $extra, array $extraAnyStatus, array $except): array
    {
        return PatternList::customizeByStatus($builtin, $extra, $extraAnyStatus, $except);
    }

    /**
     * 两类地址条目各编一条正则，外加各自的预筛正则（PatternList::gate()；写成列表，宿主追加条目时往后加一条，见 gates()）。
     *
     * @param  array{any-status: list<string>, non-success: list<string>}  $paths
     * @return array{any: string, any_gate: list<string>, non_success: string, non_success_gate: list<string>}
     */
    protected static function compilePaths(array $paths): array
    {
        return [
            'any' => PatternList::regex($paths[PatternList::ANY_STATUS]),
            'any_gate' => [PatternList::gate($paths[PatternList::ANY_STATUS])],
            'non_success' => PatternList::regex($paths[PatternList::NON_SUCCESS]),
            'non_success_gate' => [PatternList::gate($paths[PatternList::NON_SUCCESS])],
        ];
    }

    /**
     * 路径命中地址清单：命中「任意状态」组，或响应不是成功且命中「非成功」组。
     * 每组先过预筛（任一条预筛正则通过才跑完整正则）。
     *
     * 「成功」指状态码在 200–399 之内（含跳转与 304）。宿主的入口脚本（/index.php）是真实页面：
     * 它符合 "*.php"，但只在响应不是成功时才算。
     */
    protected function matchesPathList(Subject $subject, int $status): bool
    {
        $gates = $this->gates ??= $this->gates();
        $failed = $status < 200 || $status >= 400;

        foreach ($gates['any_gate'] as $gate) {
            if ($subject->pathMayMatch($gate)) {
                if (PatternList::test($this->compiled()['any'], $subject->pathCandidates())
                    && ($failed || ! $subject->isFrontController())) {
                    return true;
                }

                break;
            }
        }

        if ($failed) {
            foreach ($gates['non_success_gate'] as $gate) {
                if ($subject->pathMayMatch($gate)) {
                    return PatternList::test($this->compiled()['non_success'], $subject->pathCandidates());
                }
            }
        }

        return false;
    }

    /**
     * 两类各自的预筛正则，路径通过其中任一条才去跑那一类的完整正则。
     *
     *  - 宿主什么都没配：编译产物里的（每类一条）。
     *  - 宿主追加、排除了条目：编译产物里的，加上只由追加条目编成的一条（追加的往往只有几条，现编很便宜）。
     *    排除只会让清单变小，内置的预筛仍然覆盖得住。这样配了 lists 的宿主，正常请求也不用每次现读现编整份清单。
     *  - 没有编译产物（宿主用自己的子类替换了内置规则）：现编的完整清单里的。
     *
     * @return array{any_gate: list<string>, non_success_gate: list<string>}
     */
    protected function gates(): array
    {
        if (($gates = CompiledLists::for(static::class)) === null) {
            return $this->compiled();
        }

        if ($this->extraAnyStatus !== [] && ($extra = static::pathEntries($this->extraAnyStatus)) !== []) {
            $gates['any_gate'][] = PatternList::gate($extra);
        }

        if ($this->extra !== [] && ($extra = static::pathEntries($this->extra)) !== []) {
            $gates['non_success_gate'][] = PatternList::gate($extra);
        }

        return $gates;
    }

    /**
     * 配置里的条目，去掉查询串条目（已知漏洞探测里以 "?" 开头的，不匹配路径）。
     *
     * @return list<string>
     */
    protected static function pathEntries(array $entries): array
    {
        return array_values(array_filter(PatternList::entries($entries), fn (string $entry) => $entry[0] !== '?'));
    }
}
