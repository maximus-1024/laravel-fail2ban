<?php

namespace Maximus\Fail2Ban\Repositories\Concerns;

use InvalidArgumentException;
use Maximus\Fail2Ban\Visitor;

/**
 * 面板列表的筛选（封禁列表与攻击事件共用）：
 *
 *  - disposition：处置相等；
 *  - rule：规则标识，或 'manual'（手动封禁）；
 *  - q：$searchable 里任一字段不分大小写地包含它；能解析成 IP 时，还按它的访客键匹配
 *    （IPv6 地址能搜到所在 64 位网段的记录，`::ffff:1.2.3.4` 能搜到 1.2.3.4）。
 *
 * 值为 null 或空串的筛选项不起作用。
 */
trait FiltersRecords
{
    /**
     * @param  list<array>  $records
     * @param  array{disposition?: ?string, rule?: ?string, q?: ?string}  $filters
     * @param  list<string>  $searchable  q 做包含匹配的字段
     * @return list<array>
     */
    protected function filterRecords(array $records, array $filters, array $searchable): array
    {
        $disposition = $filters['disposition'] ?? null;
        $rule = $filters['rule'] ?? null;
        $q = mb_strtolower(trim((string) ($filters['q'] ?? '')));

        try {
            $key = $q === '' ? null : Visitor::key($q);
        } catch (InvalidArgumentException) {
            $key = null;
        }

        return array_values(array_filter($records, function (array $record) use ($disposition, $rule, $q, $key, $searchable) {
            if (filled($disposition) && $record['disposition'] !== $disposition) {
                return false;
            }

            if (filled($rule) && ($rule === 'manual' ? $record['source'] !== 'manual' : $record['rule'] !== $rule)) {
                return false;
            }

            if ($q === '' || $record['visitor'] === $key) {
                return true;
            }

            foreach ($searchable as $field) {
                if ($record[$field] !== null && str_contains(mb_strtolower($record[$field]), $q)) {
                    return true;
                }
            }

            return false;
        }));
    }
}
