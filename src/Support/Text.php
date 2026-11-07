<?php

namespace Maximus\Fail2Ban\Support;

/**
 * 访客可控的文字（地址、来源地区、浏览器标识）在记录前的清理：保证是合法 UTF-8
 * （非法字节换成替代字符，存储与 JSON 都不会出错），再按字符截断。
 */
final class Text
{
    /**
     * 浏览器标识的截断长度（攻击者信息与攻击事件共用）。
     */
    public const USER_AGENT_MAX = 255;

    /**
     * 合法 UTF-8，截断到 $max 个字符。
     */
    public static function clip(string $value, int $max): string
    {
        return mb_substr(mb_scrub($value, 'UTF-8'), 0, $max, 'UTF-8');
    }

    /**
     * 记录里的地址：截断到 PATH_MAX（fail2ban.path_max）。
     */
    public static function path(string $path): string
    {
        return static::clip($path, max(1, (int) config('fail2ban.path_max', 120)));
    }

    /**
     * 存储用的浏览器标识：截断到 USER_AGENT_MAX；没有时为 null。
     */
    public static function userAgent(mixed $agent): ?string
    {
        return is_scalar($agent) && (string) $agent !== '' ? static::clip((string) $agent, self::USER_AGENT_MAX) : null;
    }
}
