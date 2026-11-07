<?php

namespace Maximus\Fail2Ban\Rules\Support;

use InvalidArgumentException;

/**
 * 包内只读的特征清单（resources/rules/*.txt），升级扩展包时随包更新。
 *
 * 文件格式：
 *  - 一行一个条目，前后空白忽略，匹配时不分大小写。
 *  - 以 "#" 开头的行是注释。"## 标题" 是分段；地址清单（敏感文件探测、已知漏洞探测）的分段标题末尾
 *    可以带一个状态标记，决定这一段的条目在什么响应下才算（见 parseByStatus()）：
 *      "## 标题 [any-status]"   不看状态码，命中就算（恶意明确、宿主不会真有的地址）
 *      "## 标题 [non-success]"  响应不是成功（状态码不在 200–399）时才算（宿主可能真有的页面）
 *    不带标记的分段、第一个分段之前的条目都按 [non-success]（更保守，也是老格式的含义）。
 *    其它清单（扫描器特征）不看状态，标记对它不起作用。
 *  - 条目里只有首尾的 "*" 是通配符，不支持中间的 "*"。整份清单编成一条只含字面量与锚点的
 *    正则，没有可回溯的量词：
 *      "*abc*" 包含 abc        "*abc" 以 abc 结尾
 *      "abc*"  以 abc 开头      "abc"  完全等于 abc
 *
 * 文本清单是唯一的事实来源，但运行时一般不读它们：三条清单规则用的是预先编译好的
 * resources/rules/compiled.php（见 CompiledLists），opcache 把里面的正则放在共享内存里，
 * php-fpm 的每个请求拿到它们几乎不花时间。只有宿主在配置 fail2ban.lists 里追加或排除了条目时，
 * 规则才在运行时读文本清单、合并配置、编正则：parse()、customize()、regex()。
 */
final class PatternList
{
    /**
     * 状态分类：不看状态码，命中就算。
     */
    public const ANY_STATUS = 'any-status';

    /**
     * 状态分类：响应不是成功（状态码不在 200–399）时才算。没有标记的分段与宿主追加的条目默认归这一类。
     */
    public const NON_SUCCESS = 'non-success';

    /**
     * 预筛用的字符：正常接口路径里很少出现，又覆盖了「任意状态」组的绝大多数条目（文件后缀、点开头的文件）。
     * 条目里含其中任一字符时，预筛只看这个字符；不含时，预筛看条目本身（见 gate()、Subject::pathMayMatch()）。
     */
    public const GATE_CHARS = '.~';

    /**
     * 追加与排除条目：结果是（内置 + 追加）减去排除，排除按条目原文、不分大小写。
     *
     * @param  list<string>  $entries
     * @param  iterable<string>  $extra
     * @param  iterable<string>  $except
     * @return list<string>
     */
    public static function customize(array $entries, iterable $extra, iterable $except): array
    {
        $entries = array_values(array_unique([...$entries, ...self::entries($extra)]));
        $except = array_flip(array_map(strtolower(...), self::entries($except)));

        return $except === []
            ? $entries
            : array_values(array_filter($entries, fn (string $entry) => ! isset($except[strtolower($entry)])));
    }

    /**
     * 按状态分类追加与排除：宿主追加的条目默认归「非成功才算」，显式写在 $extraAnyStatus 里的归「任意状态」；
     * 排除对两类都生效。
     *
     * @param  array{any-status: list<string>, non-success: list<string>}  $lists
     * @param  iterable<string>  $extra
     * @param  iterable<string>  $extraAnyStatus
     * @param  iterable<string>  $except
     * @return array{any-status: list<string>, non-success: list<string>}
     */
    public static function customizeByStatus(array $lists, iterable $extra, iterable $extraAnyStatus, iterable $except): array
    {
        $except = self::entries($except);

        return [
            self::ANY_STATUS => self::customize($lists[self::ANY_STATUS], $extraAnyStatus, $except),
            self::NON_SUCCESS => self::customize($lists[self::NON_SUCCESS], $extra, $except),
        ];
    }

    /**
     * 配置里的条目：转成字符串、去掉首尾空白、丢掉空串与注释。
     *
     * @param  iterable<mixed>  $entries
     * @return list<string>
     */
    public static function entries(iterable $entries): array
    {
        $clean = [];

        foreach ($entries as $entry) {
            $entry = is_scalar($entry) ? trim((string) $entry) : '';

            if ($entry !== '' && $entry[0] !== '#') {
                $clean[] = $entry;
            }
        }

        return $clean;
    }

    /**
     * 解析清单文件，返回条目。
     *
     * @return list<string>
     */
    public static function parse(string $file): array
    {
        return self::entries(self::lines($file));
    }

    /**
     * @return list<string>
     */
    private static function lines(string $file): array
    {
        $lines = @file($file, FILE_IGNORE_NEW_LINES);

        if ($lines === false) {
            throw new InvalidArgumentException("Fail2Ban rule list [{$file}] could not be read.");
        }

        return $lines;
    }

    /**
     * 解析地址清单文件，按分段标题上的状态标记把条目分成两类（文件里的先后顺序保留）。
     *
     * 标题行是以 "## " 开头的行；末尾的 "[any-status]" 或 "[non-success]" 是标记，没有标记按 non-success。
     * 末尾写了别的方括号小写标记（例如拼错的 "[any]"）时报错，免得以为标记生效了其实没有。
     *
     * @return array{any-status: list<string>, non-success: list<string>}
     */
    public static function parseByStatus(string $file): array
    {
        $lists = [self::ANY_STATUS => [], self::NON_SUCCESS => []];
        $status = self::NON_SUCCESS;

        foreach (self::lines($file) as $line) {
            $line = trim($line);

            if (str_starts_with($line, '## ')) {
                $status = self::NON_SUCCESS;

                if (preg_match('~\[([a-z-]+)\]$~', $line, $match) === 1) {
                    if (! isset($lists[$match[1]])) {
                        throw new InvalidArgumentException("Unknown status marker [{$match[1]}] in fail2ban rule list [{$file}]: use [".self::ANY_STATUS.'] or ['.self::NON_SUCCESS.'].');
                    }

                    $status = $match[1];
                }

                continue;
            }

            if ($line !== '' && $line[0] !== '#') {
                $lists[$status][] = $line;
            }
        }

        return $lists;
    }

    /**
     * 预筛正则：条目里不含 GATE_CHARS 中任何字符的，取条目本身（去掉首尾通配符）当作「包含」片段，
     * 编成一条只有字面量分支、没有锚点的正则；含有的由那个字符代表（见 Subject::pathMayMatch()），不进这条正则。
     *
     * 保证：某个字符串命中 regex($entries) 时，它一定含有 GATE_CHARS 中的某个字符，或者命中这条预筛正则。
     * 只有字面量分支，PCRE 用起始字符优化，比完整清单的正则快好几倍。
     *
     * @param  list<string>  $entries
     */
    public static function gate(array $entries): string
    {
        $words = [];

        foreach ($entries as $entry) {
            $word = strtolower(trim($entry, '*'));

            if ($word === '' || str_contains($word, '*')) {
                throw new InvalidArgumentException("Invalid fail2ban rule list entry [{$entry}].");
            }

            if (strpbrk($word, self::GATE_CHARS) === false) {
                $words[$word] = preg_quote($word, '~');
            }
        }

        return $words ? '~(?:'.implode('|', $words).')~D' : '~(?!)~';
    }

    /**
     * 任一字符串符合这条正则就返回 true。调用方传入的字符串应已是小写。
     *
     * @param  iterable<string>  $subjects
     */
    public static function test(string $regex, iterable $subjects): bool
    {
        foreach ($subjects as $subject) {
            if (preg_match($regex, $subject) === 1) {
                return true;
            }
        }

        return false;
    }

    /**
     * 把条目编成一条正则：完全相等、开头、结尾、包含四类条目各成一组字面量分支，
     * 只有字面量和锚点，没有可回溯的量词。
     *
     * @param  list<string>  $entries
     */
    public static function regex(array $entries): string
    {
        $kinds = ['exact' => [], 'prefix' => [], 'suffix' => [], 'contains' => []];

        foreach ($entries as $entry) {
            $lower = strtolower($entry);
            $leading = str_starts_with($lower, '*');
            $trailing = strlen($lower) > 1 && str_ends_with($lower, '*');
            $needle = substr($lower, $leading ? 1 : 0, strlen($lower) - ($leading ? 1 : 0) - ($trailing ? 1 : 0));

            if ($needle === '' || str_contains($needle, '*')) {
                throw new InvalidArgumentException("Invalid fail2ban rule list entry [{$entry}].");
            }

            $kind = match (true) {
                $leading && $trailing => 'contains',
                $leading => 'suffix',
                $trailing => 'prefix',
                default => 'exact',
            };

            $kinds[$kind][$needle] = preg_quote($needle, '~');
        }

        $branches = [];

        if ($kinds['exact']) {
            $branches[] = '^(?:'.implode('|', $kinds['exact']).')$';
        }

        if ($kinds['prefix']) {
            $branches[] = '^(?:'.implode('|', $kinds['prefix']).')';
        }

        if ($kinds['suffix']) {
            $branches[] = '(?:'.implode('|', $kinds['suffix']).')$';
        }

        if ($kinds['contains']) {
            $branches[] = '(?:'.implode('|', $kinds['contains']).')';
        }

        // 没有条目时给一条永远不匹配的正则。D 修饰：$ 只认字符串末尾，不认末尾换行。
        return $branches ? '~'.implode('|', $branches).'~D' : '~(?!)~';
    }
}
