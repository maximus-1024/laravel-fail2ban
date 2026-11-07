<?php

namespace Maximus\Fail2Ban\Rules\Concerns;

use Maximus\Fail2Ban\Rules\Support\CompiledLists;
use Maximus\Fail2Ban\Rules\Support\PatternList;

/**
 * 带内置清单的规则（敏感文件探测、已知漏洞探测、扫描器特征）共用：
 * 内置清单文件 + 宿主在 fail2ban.lists.{规则标识} 里配置的追加与排除条目。
 *
 * 每条规则用 compile() 把清单编成自己要的正则。
 *  - 宿主没有追加也没有排除：直接取预先编译好的产物（CompiledLists），不读文件、不编正则；
 *  - 否则在第一次用到时读文本清单、合并配置、调用 compile()，结果留在规则对象上。
 */
trait UsesPatternList
{
    /**
     * 编好的清单（compile() 的结果），第一次用到时取得。
     *
     * @var array<string, string>|null
     */
    protected ?array $compiled = null;

    /**
     * @param  list<string>  $extra  宿主追加的条目
     * @param  list<string>  $except  宿主排除的内置条目（按条目原文，不分大小写）
     */
    public function __construct(protected array $extra = [], protected array $except = [])
    {
    }

    /**
     * 内置清单文件的路径。
     */
    abstract protected static function file(): string;

    /**
     * 把清单编成规则要的正则：名字 => 正则。
     * 结果只含字符串，生成编译产物时原样写进 resources/rules/compiled.php。
     *
     * @param  list<string>  $entries
     * @return array<string, string>
     */
    abstract public static function compile(array $entries): array;

    /**
     * 内置清单文件里的条目（没有追加、排除）。
     *
     * @return list<string>
     */
    public static function builtinEntries(): array
    {
        return PatternList::parse(static::file());
    }

    /**
     * 合并了追加与排除之后编好的正则。
     *
     * @return array<string, string>
     */
    protected function compiled(): array
    {
        if ($this->compiled !== null) {
            return $this->compiled;
        }

        $extra = PatternList::entries($this->extra);
        $except = PatternList::entries($this->except);

        if ($extra === [] && $except === [] && ($compiled = CompiledLists::for(static::class)) !== null) {
            return $this->compiled = $compiled;
        }

        return $this->compiled = static::compile(PatternList::customize(static::builtinEntries(), $extra, $except));
    }
}
