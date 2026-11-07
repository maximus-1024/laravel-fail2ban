<?php

namespace Maximus\Fail2Ban\Contracts;

/**
 * 封禁名单存储：命中记录、封禁键、攻击者信息、名单索引、累犯记录。
 *
 * 时间一律是 Unix 时间戳（秒，int）；时长一律是分钟。
 *
 * 往返次数（连接已建立时；新连接另有宿主连接配置决定的握手，如 SELECT、AUTH）：
 * lookup、recordHits（连同命中统计）、ban、banManually、unban、recordBlock、find、hits 各恰好一次；all 两次。
 * 实现构造时不连 Redis。
 *
 * Redis 键都不带宿主全局前缀，前缀由连接加；Lua 脚本的键全部经 KEYS 传入。
 *
 * 「封禁记录」（find()、all()、ban()、banManually()、unban() 的返回值）的形状：
 *
 *     [
 *         'visitor' => string,          // 访客键
 *         'incident' => string,         // 事件编号
 *         'source' => 'auto'|'manual',
 *         'rule' => ?string,            // 触发规则的标识；手动封禁为 null
 *         'count' => ?int,              // 触发时这条规则的命中次数；手动为 null
 *         'offense' => ?int,            // 第几次被自动封（累犯次数）；手动为 null
 *         'ip' => ?string, 'region' => ?string, 'user_agent' => ?string,
 *         'observe' => bool,            // 运行模式为观察时产生
 *         'banned_at' => int, 'unban_at' => int, 'ban_minutes' => int,
 *         'blocked' => int,             // 封禁期间被拦次数
 *         'last_blocked_at' => ?int,
 *         'operator' => ?string, 'note' => ?string,     // 手动封禁才有
 *         'first_hit_at' => ?int,       // 触发规则的首次命中时间
 *         'other_rules' => array<string, int>,          // 其它规则当时已有的命中条数（只含 >0 的）
 *         'requests' => list<array{time: int, method: ?string, path: ?string}>, // 触发规则的命中记录，按时间升序
 *     ]
 */
interface BanRepository
{
    /**
     * 进入路径的唯一一次 Redis 往返：用一个管道同时取回
     * 这个访客的封禁键内容与运行设置。
     *
     * @return array{ban: array{incident: string, banned_at: int}|null, settings: array}
     *                                                                                   settings 的形状同 SettingsRepository::all()
     */
    public function lookup(string $visitor): array;

    /**
     * 记下本次请求的全部命中，并给每条命中累加命中统计，一共一次往返。
     *
     * 每条命中各自原子执行：rule 下 dedupe 相同的命中只记一次，dedupe 为 null 时每次都新增一条；
     * 命中记录的过期时间从第一次命中算起（window），每次都检查、没有就补上；已有 $max 条时不再记。
     * 每条命中（不论是否新增）都给本小时该规则的命中数与当天三个排行加一（为 null 的类别跳过）。
     *
     * @param  string  $visitor  访客键
     * @param  list<array{rule: string, dedupe: ?string, record: array{time: int, method: string, path: string}, window: int}>  $hits
     *                                                                                                                              record 是 RuleHit::record()，只存这三项；window 是这条规则的 RULE_WINDOW（分钟）
     * @param  int  $max  HITS_MAX
     * @param  string|null  $target  攻击目标（统计排行）
     * @param  string|null  $region  来源地区（统计排行）
     * @return list<array{count: int, added: bool}> 与 $hits 一一对应：记完之后的条数，以及这次是否新增
     */
    public function recordHits(string $visitor, array $hits, int $max, ?string $target = null, ?string $region = null): array;

    /**
     * 这个访客在各规则下现有的命中记录。
     *
     * @return array<string, list<array{time: int, method: ?string, path: ?string}>> 规则标识 => 记录（按时间升序），没有记录的规则不出现
     */
    public function hits(string $visitor): array;

    /**
     * 自动封禁，原子执行。
     *
     * 封禁时长按 BanDuration::schedule() 的时长表取第「已封次数」项（超出取最后一项）：实现把时长表
     * 交给脚本，在读累犯次数的同一次原子操作里查表。$details['observe'] 为 true（观察模式下产生）时
     * 不计入累犯：按已封 0 次算时长、offense 记为 1、不读不写累犯记录。封禁键已存在时返回 null，
     * 不改动任何东西。成功时：写封禁键与攻击者信息（同过期）、加入名单索引、
     * 累犯次数加一并把过期设为「本次时长 + REPEAT_KEEP」、清空该访客在各规则下的命中记录
     * （清空前把触发规则的记录与其它规则的条数抄进攻击者信息）。
     *
     * @param  array{incident: string, rule: string, ip?: ?string, region?: ?string, user_agent?: ?string, observe?: bool}  $details
     * @param  int  $ruleBan  触发规则的 RULE_BAN（分钟）
     * @param  array{enabled: bool, factor: int, max_days: int, keep_days: int}  $repeat  累犯加长设置
     * @return array|null 封禁记录；null 表示已经被封
     */
    public function ban(string $visitor, array $details, int $ruleBan, array $repeat): ?array;

    /**
     * 手动封禁：以这次为准，覆盖已有的封禁与攻击者信息。
     *
     * 时长就是 $minutes，不加长，不计入累犯次数，不动命中记录。IP 合法性、白名单、
     * 宿主豁免由调用方先检查。
     *
     * @param  array{incident: string, operator: string, note?: ?string, ip?: ?string, region?: ?string, user_agent?: ?string, observe?: bool}  $details
     * @return array 封禁记录
     */
    public function banManually(string $visitor, array $details, int $minutes): array;

    /**
     * 解封：删除封禁键、攻击者信息、各规则的命中记录、累犯记录和索引项。
     *
     * 访客当时没有被封也会清掉命中记录与累犯记录。
     *
     * @return array|null 被解除的封禁记录；null 表示当时没有被封
     */
    public function unban(string $visitor): ?array;

    /**
     * 封禁期间被拦一次：被拦次数加一并记下时间。
     *
     * @return int|null 累计被拦次数；null 表示这个访客已经没有封禁
     */
    public function recordBlock(string $visitor): ?int;

    /**
     * 取一个访客当前的封禁记录。
     */
    public function find(string $visitor): ?array;

    /**
     * 当前被封的访客，按解封时间升序。读取时按分数清掉已过期的索引项；
     * 封禁键已不在、分数还没到的索引项只是不列出，不删（删会与并发的封禁抢同一个成员）。
     *
     * @param  array{rule?: ?string, q?: ?string}  $filters  rule 是规则标识或 'manual'；q 按访客键、IP、事件编号
     *                                                      不分大小写包含匹配，能解析成 IP 时还按它的访客键匹配
     * @return list<array>
     */
    public function all(array $filters = []): array;
}
