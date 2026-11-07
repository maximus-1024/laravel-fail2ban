<?php

namespace Maximus\Fail2Ban\Rules\Support;

use Maximus\Fail2Ban\Inspector;

/**
 * 三份内置清单的编译产物 resources/rules/compiled.php：每条清单规则编好的正则。
 *
 * 为什么要有它：php-fpm 每个请求结束都会清空进程内的静态缓存，如果每个请求都去读文本清单、
 * 编正则，正常请求的检测要多花几十微秒，404 请求多花一百多微秒。编译产物是一个只 return
 * 常量数组的 PHP 文件，opcache 把这个数组（里面是正则字符串）放进共享内存，require 它
 * 不复制、不解析；PCRE 也按正则字符串缓存编好的正则，跨请求复用。
 *
 * 文本清单 resources/rules/*.txt 仍是唯一的事实来源。改了清单要重新生成：
 *
 *     composer compile-rules        （即 php bin/compile-rules）
 *
 * 测试 CompiledListsTest 断言提交的产物与从文本清单重新生成的结果逐字节一致，忘了生成会变红。
 *
 * 宿主在 fail2ban.lists 里追加或排除了条目、或者用自己的子类替换了内置清单规则时，
 * 编译产物不适用，规则在运行时现编（见 UsesPatternList::compiled()）。
 */
final class CompiledLists
{
    /**
     * 编译产物的路径。
     */
    public const FILE = __DIR__.'/../../../resources/rules/compiled.php';

    /**
     * 本请求里已经 require 过的产物（opcache 下只是指向共享内存的一个引用）。
     *
     * @var array<class-string, array<string, string|list<string>>>|null
     */
    private static ?array $compiled = null;

    /**
     * 一个规则类的编译产物（它的 compile() 对内置清单的结果）；产物里没有这个类时返回 null。
     *
     * @param  class-string  $class
     * @return array<string, string|list<string>>|null
     */
    public static function for(string $class): ?array
    {
        return (self::$compiled ??= require self::FILE)[$class] ?? null;
    }

    /**
     * 从文本清单重新生成编译产物的源码（生成脚本与一致性测试共用，结果是确定的）。
     */
    public static function source(): string
    {
        $lists = [];

        foreach (Inspector::LIST_RULES as $id) {
            /** @var class-string<\Maximus\Fail2Ban\Rules\SensitivePath|\Maximus\Fail2Ban\Rules\KnownExploit|\Maximus\Fail2Ban\Rules\ScannerAgent> $class */
            $class = Inspector::BUILTIN[$id];

            $lists[$class] = $class::compile($class::builtinEntries());
        }

        return <<<'PHP'
            <?php

            /*
             * 由 bin/compile-rules 从 resources/rules/*.txt 生成，不要手改。
             * 改了文本清单之后运行 composer compile-rules 重新生成，并把两者一起提交。
             * 见 Maximus\Fail2Ban\Rules\Support\CompiledLists。
             */

            PHP."\nreturn ".self::export($lists, 0).";\n";
    }

    /**
     * 只有字符串键、字符串与列表的数组导出成短数组写法的 PHP 字面量。
     */
    private static function export(mixed $value, int $depth): string
    {
        if (! is_array($value)) {
            return var_export($value, true);
        }

        if ($value === []) {
            return '[]';
        }

        $indent = str_repeat('    ', $depth + 1);
        $list = array_is_list($value);
        $lines = [];

        foreach ($value as $key => $item) {
            $lines[] = $indent.($list ? '' : var_export($key, true).' => ').self::export($item, $depth + 1).',';
        }

        return "[\n".implode("\n", $lines)."\n".str_repeat('    ', $depth).']';
    }
}
