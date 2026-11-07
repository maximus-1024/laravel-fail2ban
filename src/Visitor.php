<?php

namespace Maximus\Fail2Ban;

use InvalidArgumentException;
use Symfony\Component\HttpFoundation\IpUtils;

/**
 * 访客键：IPv4 原样；IPv6 取前 64 位网段，形如 `2001:db8:4c2:91::/64`。
 *
 * 中间件、手动封禁、解封、白名单都用它把 IP 变成同一个键。
 */
class Visitor
{
    /**
     * 把 IP（或已经是访客键的 `xxxx::/64`）规范化为访客键。
     *
     * IPv4 映射的 IPv6（`::ffff:203.0.113.7`）按 IPv4 处理。
     *
     * @throws \InvalidArgumentException 不是合法的 IP 或访客键
     */
    public static function key(string $ip): string
    {
        $ip = trim($ip);

        if (str_ends_with($ip, '/64')) {
            $network = substr($ip, 0, -3);

            if (filter_var($network, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false) {
                return static::ipv6Network($network);
            }

            throw new InvalidArgumentException("Invalid visitor key [{$ip}].");
        }

        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
            return $ip;
        }

        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) === false) {
            throw new InvalidArgumentException("Invalid IP address [{$ip}].");
        }

        $binary = inet_pton($ip);

        // ::ffff:a.b.c.d
        if (str_starts_with($binary, str_repeat("\0", 10)."\xff\xff")) {
            return inet_ntop(substr($binary, 12));
        }

        return static::ipv6Network($ip);
    }

    /**
     * 规范化的单个地址（不收窄到网段）：IPv4 映射的 IPv6（`::ffff:203.0.113.7`）换成 IPv4，
     * 其余 IPv6 写成小写的压缩形式。交给宿主豁免回调、按真实地址查白名单时用它。
     *
     * @throws \InvalidArgumentException 不是合法的 IP
     */
    public static function ip(string $ip): string
    {
        $ip = trim($ip);

        if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
            throw new InvalidArgumentException("Invalid IP address [{$ip}].");
        }

        $binary = inet_pton($ip);

        if (strlen($binary) === 16 && str_starts_with($binary, str_repeat("\0", 10)."\xff\xff")) {
            $binary = substr($binary, 12);
        }

        return inet_ntop($binary);
    }

    /**
     * 访客键代表的地址：IPv4 键原样返回，IPv6 键返回网段的首地址（去掉 `/64`）。
     */
    public static function address(string $key): string
    {
        return str_ends_with($key, '/64') ? substr($key, 0, -3) : $key;
    }

    /**
     * 白名单条目（IP 或 CIDR）是否覆盖这个地址或访客键——白名单匹配的唯一一处实现。
     *
     *  - 单个地址（ip() 规范化过的）与 IPv4 访客键：条目包含这个地址；
     *  - IPv6 访客键（一个 /64 网段）：条目包含网段首地址，或条目的地址落在这个网段里
     *    （加白名单时据此解封：否则白名单里的那个地址仍会被这个网段的封禁拦住）。
     */
    public static function covers(string $entry, string $visitor): bool
    {
        if (IpUtils::checkIp(static::address($visitor), $entry)) {
            return true;
        }

        return str_ends_with($visitor, '/64')
            && IpUtils::checkIp(explode('/', $entry, 2)[0], $visitor);
    }

    /**
     * IPv6 地址的 64 位网段。
     */
    protected static function ipv6Network(string $ip): string
    {
        $network = substr(inet_pton($ip), 0, 8).str_repeat("\0", 8);

        return inet_ntop($network).'/64';
    }
}
