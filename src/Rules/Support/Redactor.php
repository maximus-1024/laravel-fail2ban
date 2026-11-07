<?php

namespace Maximus\Fail2Ban\Rules\Support;

/**
 * 记录前给地址里看起来像凭据的查询参数值打码。
 *
 * 只在有规则命中、要生成展示用的请求记录时调用（RuleHit::make），正常请求不经过这里。
 * 参数名保留，值换成 MASK；其它参数与路径原样不动，运维仍能看出对方在探测什么。
 *
 * 参数名的判断：先按 URL 解码、转小写、把 "-" 当 "_"；形如 a[b][c] 的数组参数看最里面的 b、c；
 * 然后与 NAMES 完全相等，或以 SUFFIXES 中的一个结尾，就算凭据。宁可多打码：多打一个不是
 * 凭据的值只是少一点排查信息，漏打一个凭据就是把它写进了 Redis 与面板。
 */
final class Redactor
{
    /**
     * 替换凭据值的固定掩码。
     */
    public const MASK = '***';

    /**
     * 完全相等就算凭据的参数名（小写，"-" 已换成 "_"）。
     */
    public const NAMES = [
        'sign', 'signature', 'sig',
        'token', 'access_token', 'refresh_token', 'id_token', 'auth_token', 'api_token', 'xsrf_token', 'csrf_token', '_token',
        'key', 'api_key', 'apikey', 'app_key', 'appkey', 'secret', 'app_secret', 'appsecret', 'client_secret', 'private_key',
        'password', 'passwd', 'pwd', 'pass', 'passphrase',
        'auth', 'authorization', 'credential', 'credentials',
        'session', 'sessionid', 'session_id', 'phpsessid',
    ];

    /**
     * 以这些结尾就算凭据的参数名后缀，例如 merchant_secret、x_api_key、user_password。
     */
    public const SUFFIXES = ['_token', '_secret', '_key', '_password', '_passwd', '_pwd', '_sign', '_signature'];

    /**
     * 给「路径加查询参数」里的凭据参数值打码。没有查询串时原样返回。
     */
    public static function uri(string $uri): string
    {
        $at = strpos($uri, '?');

        if ($at === false) {
            return $uri;
        }

        $pairs = explode('&', substr($uri, $at + 1));

        foreach ($pairs as $i => $pair) {
            $eq = strpos($pair, '=');

            if ($eq !== false && $eq < strlen($pair) - 1 && static::isCredential(substr($pair, 0, $eq))) {
                $pairs[$i] = substr($pair, 0, $eq + 1).self::MASK;
            }
        }

        return substr($uri, 0, $at + 1).implode('&', $pairs);
    }

    /**
     * 一个原样（可能带百分号编码）的参数名是不是凭据。
     */
    public static function isCredential(string $name): bool
    {
        $name = str_replace('-', '_', strtolower(trim(urldecode(urldecode($name)))));

        $names = [$name];

        // a[b][c]：也看每一层方括号里的名字
        if (str_contains($name, '[') && preg_match_all('~\[([^\[\]]*)\]~', $name, $matches)) {
            $names = array_merge([strstr($name, '[', true)], $matches[1]);
        }

        foreach ($names as $part) {
            if ($part === '') {
                continue;
            }

            if (in_array($part, self::NAMES, true)) {
                return true;
            }

            foreach (self::SUFFIXES as $suffix) {
                if (str_ends_with($part, $suffix)) {
                    return true;
                }
            }
        }

        return false;
    }
}
