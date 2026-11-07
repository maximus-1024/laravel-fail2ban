<?php

namespace Maximus\Fail2Ban;

/**
 * 需要原子性的 Redis 脚本（写法照 Laravel\Horizon\LuaScripts）。
 *
 * 所有键都通过 KEYS 传入，这样连接上的全局前缀对脚本同样生效；脚本里不拼键名。
 */
class LuaScripts
{
    /**
     * 记一次命中。
     *
     * 条数未到上限时用 HSETNX 写入（相同去重键只算一次）；无论是否写入，
     * 只要键存在而没有过期时间就补上——过期从第一次命中算起，且不会留下永不过期的键。
     *
     * KEYS[1] - 命中记录哈希 fail2ban:hits:{规则}:{访客键}
     * ARGV[1] - 字段名；空串表示「每次都算」，由脚本生成不重复的字段
     * ARGV[2] - 展示用的记录（JSON）
     * ARGV[3] - 过期秒数（这条规则的 RULE_WINDOW）
     * ARGV[4] - 最多记录的条数（HITS_MAX）
     *
     * 返回 {记完之后的条数, 这次是否新增(1/0)}
     *
     * @return string
     */
    public static function recordHit()
    {
        return <<<'LUA'
            local count = redis.call('hlen', KEYS[1])
            local added = 0

            if count < tonumber(ARGV[4]) then
                local field = ARGV[1]

                if field == '' then
                    field = 'n:' .. (count + 1)
                end

                added = redis.call('hsetnx', KEYS[1], field, ARGV[2])
                count = count + added
            end

            if redis.call('ttl', KEYS[1]) == -1 then
                redis.call('expire', KEYS[1], ARGV[3])
            end

            return {count, added}
LUA;
    }

    /**
     * 自动封禁，一次往返、原子执行。
     *
     * 读累犯次数并查时长表（BanDuration::schedule()），然后封禁键「不存在才写」；
     * 已存在时返回 false 且不改动任何东西。写入成功时：累犯次数加一并设过期、
     * 把触发规则的命中记录与其它规则的命中条数抄进攻击者信息、写攻击者信息（与封禁键同过期）、
     * 加入名单索引、清空各规则的命中记录。判断与写入在同一个脚本里，不会出现半截状态。
     *
     * 观察模式下的封禁不计入累犯（ARGV[5] 为 0）：按已封 0 次查时长表（不加长），
     * 「第几次被封」记为 1，累犯记录既不读也不写——观察期反复触发的访客，切到拦截后第一次被封仍按第 1 次算。
     *
     * KEYS[1]  - 封禁键 fail2ban:ban:{访客键}
     * KEYS[2]  - 攻击者信息 fail2ban:info:{访客键}
     * KEYS[3]  - 名单索引 fail2ban:bans
     * KEYS[4]  - 累犯记录 fail2ban:repeat:{访客键}
     * KEYS[5]  - 触发规则的命中记录
     * KEYS[6…] - 其它规则的命中记录（与其它规则的标识一一对应）
     * ARGV[1]  - 事件编号
     * ARGV[2]  - 封禁时间
     * ARGV[3]  - 访客键（索引成员）
     * ARGV[4]  - REPEAT_KEEP 秒数
     * ARGV[5]  - 是否计入累犯：1 计入，0 不计入（观察模式）
     * ARGV[6]  - 时长表的项数 m
     * ARGV[7…6+m]      - 时长表（分钟）
     * ARGV[7+m]        - 其它规则的个数 n
     * ARGV[8+m…7+m+n]  - 其它规则的标识
     * ARGV[8+m+n…]     - 攻击者信息的其余字段与值，成对出现
     *
     * 返回写好的攻击者信息（HGETALL 的扁平列表），或 false 表示已被封
     *
     * @return string
     */
    public static function ban()
    {
        return <<<'LUA'
            local counted = ARGV[5] == '1'
            local m = tonumber(ARGV[6])
            local previous = 0

            if counted then
                previous = tonumber(redis.call('get', KEYS[4])) or 0
            end

            local minutes = tonumber(ARGV[7 + math.min(previous, m - 1)])
            local seconds = minutes * 60
            local now = tonumber(ARGV[2])

            if not redis.call('set', KEYS[1], ARGV[1] .. '|' .. ARGV[2], 'EX', seconds, 'NX') then
                return false
            end

            local offense = 1

            if counted then
                offense = redis.call('incr', KEYS[4])
                redis.call('expire', KEYS[4], seconds + tonumber(ARGV[4]))
            end

            local requests = redis.call('hvals', KEYS[5])
            local n = tonumber(ARGV[7 + m])
            local others = {}

            for i = 1, n do
                local count = redis.call('hlen', KEYS[5 + i])

                if count > 0 then
                    table.insert(others, cjson.encode(ARGV[7 + m + i]) .. ':' .. count)
                end
            end

            local info = {
                'incident', ARGV[1],
                'banned_at', ARGV[2],
                'unban_at', string.format('%d', now + seconds),
                'ban_minutes', string.format('%d', minutes),
                'count', #requests,
                'offense', offense,
                'blocked', 0,
                'requests', '[' .. table.concat(requests, ',') .. ']',
                'other_rules', '{' .. table.concat(others, ',') .. '}',
            }

            for i = 8 + m + n, #ARGV, 2 do
                table.insert(info, ARGV[i])
                table.insert(info, ARGV[i + 1])
            end

            redis.call('del', KEYS[2])
            redis.call('hset', KEYS[2], unpack(info))
            redis.call('expire', KEYS[2], seconds)
            redis.call('zadd', KEYS[3], now + seconds, ARGV[3])

            for i = 5, #KEYS do
                redis.call('del', KEYS[i])
            end

            return redis.call('hgetall', KEYS[2])
LUA;
    }

    /**
     * 手动封禁，一次往返、原子执行：覆盖封禁键与攻击者信息，加入名单索引。
     * 不碰累犯记录与命中记录。
     *
     * KEYS[1] - 封禁键
     * KEYS[2] - 攻击者信息
     * KEYS[3] - 名单索引
     * ARGV[1] - 封禁键的内容
     * ARGV[2] - 封禁秒数
     * ARGV[3] - 解封时间
     * ARGV[4] - 访客键
     * ARGV[5…] - 攻击者信息的字段与值，成对出现
     *
     * @return string
     */
    public static function banManually()
    {
        return <<<'LUA'
            redis.call('set', KEYS[1], ARGV[1], 'EX', ARGV[2])
            redis.call('del', KEYS[2])
            redis.call('hset', KEYS[2], unpack(ARGV, 5))
            redis.call('expire', KEYS[2], ARGV[2])
            redis.call('zadd', KEYS[3], ARGV[3], ARGV[4])

            return 1
LUA;
    }

    /**
     * 解封，一次往返、原子执行：取回封禁键内容与攻击者信息，然后删除
     * 封禁键、攻击者信息、累犯记录、各规则的命中记录与索引项。
     *
     * KEYS[1] - 封禁键
     * KEYS[2] - 攻击者信息
     * KEYS[3] - 名单索引
     * KEYS[4…] - 累犯记录与各规则的命中记录
     * ARGV[1] - 访客键
     *
     * 返回 {封禁键内容（没有时为空串）, 攻击者信息（HGETALL 的扁平列表）}
     *
     * @return string
     */
    public static function unban()
    {
        return <<<'LUA'
            local ban = redis.call('get', KEYS[1]) or ''
            local info = redis.call('hgetall', KEYS[2])

            redis.call('del', KEYS[1], KEYS[2], unpack(KEYS, 4))
            redis.call('zrem', KEYS[3], ARGV[1])

            return {ban, info}
LUA;
    }

    /**
     * 封禁期间被拦一次：被拦次数加一并记下时间。
     *
     * 攻击者信息不存在（已到期或已解封）时什么都不做，避免写出没有过期时间的键。
     *
     * KEYS[1] - 攻击者信息 fail2ban:info:{访客键}
     * ARGV[1] - 本次被拦的时间
     *
     * 返回累计被拦次数，或 false 表示攻击者信息不存在
     *
     * @return string
     */
    public static function recordBlock()
    {
        return <<<'LUA'
            if redis.call('exists', KEYS[1]) == 0 then
                return false
            end

            local blocked = redis.call('hincrby', KEYS[1], 'blocked', 1)
            redis.call('hset', KEYS[1], 'last_blocked_at', ARGV[1])

            return blocked
LUA;
    }

    /**
     * 一次统计写入，一次往返、原子执行：本小时的一个字段加一并设过期；
     * 当天的各个排行加一、只留前 ARGV[4] 名并设过期。
     *
     * KEYS[1]  - 小时计数 fail2ban:stats:{小时}
     * KEYS[2…] - 排行 fail2ban:top:{类别}:{日期}
     * ARGV[1]  - 小时计数里的字段
     * ARGV[2]  - 小时计数的过期时刻
     * ARGV[3]  - 排行的过期时刻
     * ARGV[4]  - 排行保留的名次
     * ARGV[5…] - 各排行要加一的成员（与 KEYS[2…] 一一对应）
     *
     * @return string
     */
    public static function incrementStats()
    {
        return <<<'LUA'
            redis.call('hincrby', KEYS[1], ARGV[1], 1)
            redis.call('expireat', KEYS[1], ARGV[2])

            for i = 2, #KEYS do
                redis.call('zincrby', KEYS[i], 1, ARGV[3 + i])
                redis.call('zremrangebyrank', KEYS[i], 0, -(tonumber(ARGV[4]) + 1))
                redis.call('expireat', KEYS[i], ARGV[3])
            end

            return 1
LUA;
    }

    /**
     * 在历史列表里找到以 ARGV[1] 开头的那一条，把其中第一处 ARGV[2] 换成 ARGV[3]。
     *
     * 列表最多 HISTORY_LIMIT 条，按内容定位而不是按下标，所以并发的 LPUSH 不会改错条目。
     *
     * KEYS[1] - 列表 fail2ban:events
     * ARGV[1] - 条目开头，例如 {"id":"BAN-20261106-7K2M9Q",
     * ARGV[2] - 要替换的片段，例如 "disposition":"banned"
     * ARGV[3] - 替换成的片段
     *
     * 返回 1 表示改了，0 表示没找到
     *
     * @return string
     */
    public static function replaceInList()
    {
        return <<<'LUA'
            local items = redis.call('lrange', KEYS[1], 0, -1)

            for i, item in ipairs(items) do
                if string.sub(item, 1, #ARGV[1]) == ARGV[1] then
                    local from, to = string.find(item, ARGV[2], 1, true)

                    if not from then
                        return 0
                    end

                    redis.call('lset', KEYS[1], i - 1, string.sub(item, 1, from - 1) .. ARGV[3] .. string.sub(item, to + 1))

                    return 1
                end
            end

            return 0
LUA;
    }
}
