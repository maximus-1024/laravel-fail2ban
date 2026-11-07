<?php

namespace Maximus\Fail2Ban\Rules\Concerns;

use Maximus\Fail2Ban\Rules\Support\CompiledLists;
use Maximus\Fail2Ban\Rules\Support\PatternList;

/**
 * 带内置清单的规则（敏感文件探测、已知漏洞探测、扫描器特征）共用：
 * 内置清单文件 + 宿主在 fail2ban.lists.{规则标识} 里配置的追加（extra、extra_any_status）与排除（except）条目。
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
     * @var array<string, string|list<string>>|null
     */
    protected ?array $compiled = null;

    /**
     * @param  list<string>  $extra  宿主追加的条目（地址清单里归「响应不是成功才算」）
     * @param  list<string>  $except  宿主排除的条目（按条目原文，不分大小写）
     * @param  list<string>  $extraAnyStatus  宿主追加的、不看状态码的条目（地址清单里归「任意状态」；
     *                                        扫描器特征本来就不看状态码，与 $extra 相同）
     */
    public function __construct(protected array $extra = [], protected array $except = [], protected array $extraAnyStatus = [])
    {
    }

    /**
     * 内置清单文件的路径。
     */
    abstract protected static function file(): string;

    /**
     * 把清单编成规则要的正则：名字 => 正则（或正则的列表）。
     * 结果只含字符串与字符串列表，生成编译产物时原样写进 resources/rules/compiled.php。
     *
     * @param  array  $entries  builtinEntries() 形状的条目
     * @return array<string, string|list<string>>
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
     * 把宿主追加、排除的条目合进内置条目。清单不看状态码，两种追加一样对待。
     *
     * @param  list<string>  $extra
     * @param  list<string>  $extraAnyStatus
     * @param  list<string>  $except
     */
    protected static function customizeEntries(array $builtin, array $extra, array $extraAnyStatus, array $except): array
    {
        return PatternList::customize($builtin, [...$extra, ...$extraAnyStatus], $except);
    }

    /**
     * 合并了追加与排除之后编好的正则。
     *
     * @return array<string, string|list<string>>
     */
    protected function compiled(): array
    {
        if ($this->compiled !== null) {
            return $this->compiled;
        }

        // 什么都没配（绝大多数宿主）：直接取编译产物。地址清单规则现在每个请求都要用到它，省掉下面三次清理。
        if ($this->extra === [] && $this->extraAnyStatus === [] && $this->except === []
            && ($compiled = CompiledLists::for(static::class)) !== null) {
            return $this->compiled = $compiled;
        }

        $extra = PatternList::entries($this->extra);
        $extraAnyStatus = PatternList::entries($this->extraAnyStatus);
        $except = PatternList::entries($this->except);

        if ($extra === [] && $extraAnyStatus === [] && $except === [] && ($compiled = CompiledLists::for(static::class)) !== null) {
            return $this->compiled = $compiled;
        }

        return $this->compiled = static::compile(static::customizeEntries(static::builtinEntries(), $extra, $extraAnyStatus, $except));
    }
}
