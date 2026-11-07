<?php

namespace Maximus\Fail2Ban\Contracts;

/**
 * 攻击事件：列表 fail2ban:events，新的在前，只留 HISTORY_LIMIT 条。
 *
 * 「事件」的形状（record() 的返回值，find()、paginate() 的条目）：
 *
 *     [
 *         'id' => 'BAN-20261106-7K2M9Q',
 *         'time' => int,                       // 事件时间
 *         'visitor' => string, 'ip' => ?string, 'region' => ?string,
 *         'rule' => ?string,                   // 规则标识；手动封禁为 null
 *         'source' => 'auto'|'manual',
 *         'count' => ?int,
 *         'disposition' => 'banned'|'expired'|'unbanned'|'exempted'|'recorded',
 *         'observe' => bool,
 *         'operator' => ?string, 'note' => ?string,
 *         'user_agent' => ?string, 'first_hit_at' => ?int,
 *         'banned_at' => ?int, 'unban_at' => ?int, 'ban_minutes' => ?int, 'offense' => ?int,
 *         'other_rules' => array<string, int>,
 *         'requests' => list<array{time: int, method: ?string, path: ?string}>,
 *     ]
 *
 * 'expired' 不存储：存的是 'banned'，读取时 unban_at 已过就显示为 'expired'。
 * 浏览器标识由存储层截断（Support\Text::userAgent()，与攻击者信息同一个上限），调用方传原值。
 * 被拦次数不在事件里，封禁还在时从 BanRepository::find() 取（incident 相同才是同一次封禁）。
 */
interface IncidentRepository
{
    /**
     * 生成一个新的事件编号，形如 BAN-20261106-7K2M9Q（日期加六位随机大写字母数字）。
     */
    public function nextId(): string;

    /**
     * 写一条事件，放在最前；超过 HISTORY_LIMIT 的最旧条目被丢弃。
     *
     * 只保存上面列出的字段，其它键（例如封禁记录里的 incident、blocked）被忽略；
     * 缺 id 时自动生成，缺 time 时取现在。可以直接把封禁记录并进来：
     * `record(['id' => $ban['incident'], 'disposition' => 'banned', 'time' => $ban['banned_at']] + $ban)`。
     *
     * @param  array{disposition: 'banned'|'exempted'|'recorded', visitor: string}  $incident
     * @return array 规范化后的事件
     */
    public function record(array $incident): array;

    /**
     * 按事件编号取一条。
     */
    public function find(string $id): ?array;

    /**
     * 分页与筛选，新的在前。页码与每页条数由调用方限定。
     *
     * @param  array{disposition?: ?string, rule?: ?string, q?: ?string}  $filters
     *                                                                             rule 是规则标识或 'manual'；q 按事件编号、访客键、IP 做不分大小写的包含匹配；
     *                                                                             q 能解析成 IP 时还按它的访客键匹配（IPv6 地址能搜到所在网段的事件）
     * @return array{data: list<array>, total: int, page: int, per_page: int, history_limit: int}
     */
    public function paginate(array $filters = [], int $page = 1, int $perPage = 20): array;

    /**
     * 把一条处置为「已封禁」的事件改为「已解封」。
     *
     * @return bool 是否改了（找不到，或处置不是 banned 时为 false）
     */
    public function markUnbanned(string $id): bool;
}
