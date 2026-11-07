<?php

namespace Maximus\Fail2Ban\Rules\Support;

use InvalidArgumentException;

/**
 * 包内只读的特征清单（resources/rules/*.txt），升级扩展包时随包更新。
 *
 * 文件格式：
 *  - 一行一个条目，前后空白忽略，匹配时不分大小写。
 *  - 以 "#" 开头的行是注释（"## 标题" 只是给人看的分段）。
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
        $lines = @file($file, FILE_IGNORE_NEW_LINES);

        if ($lines === false) {
            throw new InvalidArgumentException("Fail2Ban rule list [{$file}] could not be read.");
        }

        return self::entries($lines);
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
