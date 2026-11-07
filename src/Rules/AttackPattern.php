<?php

namespace Maximus\Fail2Ban\Rules;

use Illuminate\Http\Request;
use Maximus\Fail2Ban\Contracts\Rule;
use Maximus\Fail2Ban\Rules\Support\Subject;
use Symfony\Component\HttpFoundation\Response;

/**
 * 攻击特征：路径或查询参数里出现高把握的 SQL 注入、跨站脚本、路径穿越、命令执行、PHP 注入片段，
 * 模板注入的算术探针，云元数据地址或盲注回连域名；
 * 或请求方法是 CONNECT、TRACE；或把本站当代理用（请求行里是完整的外部网址）。
 *
 * 不看状态码，不读请求正文。PUT、PATCH、DELETE 是正常方法。参数值是一个网址不算：
 * 不收「值是 http(s) 网址」这类远程包含特征，支付回调地址本来就是网址。
 *
 * 只收高把握的片段：误伤商户比漏报更糟。CrowdSec 清单里的 substr(、md5(、upper(、
 * hex(、<a、<p、<br、<div 这类在正常文字里也会出现的片段没收。
 *
 * 性能：先用不带正则的预筛（见 SUSPICIOUS_*），绝大多数正常请求在预筛就结束；
 * 过了预筛才进那一条合并好的正则，而且每一段（路径的各层、每个参数名与值的各层）都先单独预筛，
 * 没有可疑字符与片段的段不进正则——垫进去的长参数不花正则的时间（见 Subject 的 URI_MAX）。
 */
class AttackPattern implements Rule
{
    /**
     * 预筛用的字符：所有特征都至少含其中一个字符，或含 SUSPICIOUS_FRAGMENTS 里的一个片段。
     * "%" 表示解一层之后还有编码（多层编码），"\0" 是空字节。
     */
    protected const SUSPICIOUS_CHARS = "'\"<>;|`\$({%\0";

    /**
     * 预筛用的片段（小写）。不含上面字符的特征，靠这些片段进入正则。
     */
    protected const SUSPICIOUS_FRAGMENTS = [
        'union', 'information_schema', '@@', 'outfile', 'dumpfile', 'xp_cmdshell',
        'script:', 'document.',
        '..', '/etc/', '/proc/', '.ini', 'c:/', 'c:\\',
        'php://', 'phar://', 'expect://', 'glob://', 'zip://', 'gopher://', 'dict://', 'file://',
        'zlib://', 'bzip2://', 'rar://', 'ogg://', 'ssh2.',
        '&&', 'call_user_func_array', 'invokefunction', 'allow_url_include', 'auto_prepend_file', 'java.lang',
        'auto_append_file', 'cgi.', 'open_basedir', 'disable_functions', 'safe_mode', 'data://',
        '169.254.', 'metadata.google', 'instance-data',
        'oast', 'burpcollaborator', 'interact.sh', 'dnslog', 'ceye.io', 'dnshook',
    ];

    /**
     * 特征正则，按类别分组。匹配对象已经小写、去空字节，SQL 注释已换成空格。
     * 所有量词要么有上界，要么前后字符集互斥，不会灾难性回溯。
     */
    protected const PATTERNS = [
        'SQL 注入' => [
            '\bunion\s+(?:all\s+|distinct\s+)?select\b',
            '\binformation_schema\b',
            '@@(?:version|datadir|hostname|basedir)\b',
            '\b(?:pg_)?sleep\s*\(\s*\d',
            '\bbenchmark\s*\(\s*\d',
            '\bwaitfor\s+delay\s+[\'"]',
            '\b(?:load_file|extractvalue|updatexml)\s*\(',
            '\binto\s+(?:out|dump)file\b',
            '\bxp_cmdshell\b',
            '[\'"]\s*(?:or|and)\s+[\'"]?\d+[\'"]?\s*=\s*[\'"]?\d',
        ],
        '跨站脚本' => [
            '<script[\s/>]',
            '<(?:iframe|object|embed|svg|frameset|applet)[\s/>]',
            '<[a-z][a-z0-9]{0,15}[\s/][^>]{0,100}?\bon[a-z]{3,20}\s*=',
            '\b(?:java|vb)script:',
            '\b(?:alert|prompt|confirm)\s*[(`]\s*(?:\d|[\'"`/)]|document|window)',
            '\bdocument\.(?:cookie|domain)\b',
        ],
        '路径穿越与本地文件' => [
            '(?:^|[/\\\\=])\.\.[/\\\\]',
            '/etc/(?:passwd|shadow|group|hosts)\b',
            '/proc/self/',
            '\b(?:win|boot|system)\.ini\b',
            '\bc:[/\\\\](?:windows|winnt|inetpub)\b',
            '\b(?:php|phar|expect|glob|zip|gopher|dict|file)://',
        ],
        '命令执行' => [
            '(?:[;|`]|&&|\$\()\s*(?:whoami\b|uname\s+-[a-z]|cat\s+/etc/|(?:/usr)?/bin/(?:ba|da|z|k)?sh\b|nc(?:at)?\s+-[a-z]*e\b|(?:wget|curl)\s+(?:-\S+\s+){0,4}(?:https?|ftp)://|chmod\s+(?:\+x|[0-7]{3,4})\b|rm\s+-(?:rf|fr)\b|ping\s+-[cn]\s*\d|nslookup\s+\S)',
            '\$\{ifs\}|\$ifs\$',
            '\(\)\s*\{[^}]{0,20}\}\s*;',
            '<\?php\b',
            '\b(?:shell_exec|passthru|proc_open|popen|pcntl_exec|base64_decode|create_function)\s*\(',
            '\bcall_user_func_array\b',
            '\binvokefunction\b',
            '\b(?:allow_url_include|auto_prepend_file)\b',
            '[$%]\{\s*\(\s*#',
            '\bjava\.lang\.(?:runtime|processbuilder)\b',
        ],
        // 2026-11-07 按 OWASP CRS 的 PHP 规则补充（rules/REQUEST-933-APPLICATION-ATTACK-PHP.conf），
        // 只取正常参数里不会出现的写法；CRS 933150、933160 里 exec、system、md5、substr 这类
        // 常见单词形式的函数名不收。
        'PHP 注入' => [
            '<\?=',                                                        // 933100 短输出标签
            '\bphpinfo\s*\(',                                               // 933160
            '\$_(?:get|post|request|cookie|files|server|env|session)\s*\[', // 933130 超全局变量，要求后面跟 [
            '\b[oc]:\d{1,5}:"[a-z0-9_\\\\]{1,128}":\d{1,5}:\{',               // 933170 序列化对象
            '\b(?:compress\.)?(?:zlib|bzip2)://|\b(?:rar|ogg)://|\bssh2\.(?:shell|exec|tunnel|sftp|scp)://', // 933200 包装器
            // 2026-11-07 补充。933120 的配置指令里其余几个（display_errors、precision 这类常见词不收）：
            // 「指令=值」写在同一段里（PHP-CGI 参数注入要编码等号，如 nuclei CVE-2024-4577 的 cgi.force_redirect%3d0），
            // 或前面带 -d 开关。普通的 ?safe_mode=1 拆成参数名与值两段，不算。
            '\b(?:auto_append_file|cgi\.force_redirect|cgi\.redirect_status_env|open_basedir|disable_functions|safe_mode)\s*=',
            '(?:^|\s)[-\xad]d\s*(?:auto_append_file|cgi\.force_redirect|cgi\.redirect_status_env|open_basedir|disable_functions|safe_mode)\b',
            // PHP 的 data:// 包装器（带双斜杠）。浏览器的 data URI（data:image/png;base64,…）不带双斜杠，不算。
            '\bdata://',
        ],
        // 2026-11-07 按 OWASP CRS 934180、934200（服务端模板注入）补充：只收「两个整数相乘」的探针，
        // 如 {{7*7}}、${7*7}、#{7*7}、<%= 7*7 %>；带括号的通用写法（Vue、Handlebars 的文字里会有）不收。
        '模板注入探针' => [
            '\{\{\s*\d{1,10}\s*\*\s*\d{1,10}\s*\}\}',
            '[$#]\{\s*\d{1,10}\s*\*\s*\d{1,10}\s*\}',
            '<%=?\s*\d{1,10}\s*\*\s*\d{1,10}\s*%>',
        ],
        // 2026-11-07 补充。云元数据地址：OWASP CRS ssrf.data（934110 用），只收这几个具体主机，
        // 参数值是任意网址仍不算。盲注回连域名：Sigma net_dns_external_service_interaction_domains.yml，
        // 不收 webhook.site（商户调试回调会用）与 canarytokens.com（有人拿来做蜜标测试）。
        '服务端请求伪造与回连' => [
            '\b169\.254\.(?:169\.254|170\.2)\b',
            '\bmetadata\.google\.internal\b',
            '//instance-data\b',
            '\.(?:oast\.(?:fun|live|me|online|pro|site)|oastify\.com|burpcollaborator\.net|interact\.sh|dnslog\.cn|ceye\.io|dnshook\.site)\b',
        ],
    ];

    /**
     * 合并好的正则，第一次用到时构建。
     */
    protected static ?string $regex = null;

    public function id(): string
    {
        return 'attack-pattern';
    }

    public function name(): string
    {
        return '攻击特征';
    }

    public function description(): string
    {
        return '路径或查询参数里出现 SQL 注入、跨站脚本、路径穿越、命令执行、PHP 代码注入的片段、模板注入探针、云元数据地址或盲注回连域名，或请求方法是 CONNECT、TRACE，或把本站当代理用时记一次；同一个「路径加查询参数」只算一次。参数值是普通网址不算。';
    }

    public function isPathRule(): bool
    {
        return false;
    }

    public function matches(Request $request, Response $response): bool
    {
        $subject = Subject::of($request);

        $method = $subject->method();

        if ($method === 'CONNECT' || $method === 'TRACE' || $this->isProxyRequest($subject)) {
            return true;
        }

        if (! $this->suspicious($subject)) {
            return false;
        }

        $regex = static::$regex ??= static::compile();

        foreach ([$subject->pathLayers(), $subject->queryPieces()] as $layers) {
            foreach ($layers as $layer) {
                if (static::containsSuspicious($layer) && preg_match($regex, static::stripSqlComments($layer)) === 1) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * 完整地址（路径加查询参数）的摘要。查询串里可能有签名、令牌这类凭据，
     * 去重键会存进 Redis，所以一律只存摘要，不存原文。
     */
    public function key(Request $request): ?string
    {
        return Subject::digest(Subject::of($request)->uri());
    }

    public function countMode(): string
    {
        return self::COUNT_DISTINCT;
    }

    /**
     * 不带正则的预筛：把整个地址解一层、转小写，看有没有可疑字符或片段。
     */
    protected function suspicious(Subject $subject): bool
    {
        return static::containsSuspicious(strtolower(urldecode($subject->uri())));
    }

    /**
     * 小写文本里有没有可疑字符或片段。每条特征都至少含其中之一，所以没有的文本一定不匹配特征正则。
     */
    protected static function containsSuspicious(string $text): bool
    {
        if (strpbrk($text, static::SUSPICIOUS_CHARS) !== false) {
            return true;
        }

        foreach (static::SUSPICIOUS_FRAGMENTS as $fragment) {
            if (str_contains($text, $fragment)) {
                return true;
            }
        }

        return false;
    }

    /**
     * 把本站当代理用：请求行上的请求目标是一个完整的 http(s) 网址（absolute-form）。
     *
     * 正常客户端（浏览器、curl、各语言的 HTTP 库）直连源站时只发 "/path" 形式，只有发给
     * 代理时才发完整网址，所以出现就算，与 CrowdSec http-open-proxy 的口径相同。
     * 不比较主机名：探测开放代理时对方会把 Host 也设成目标站，比较了反而漏掉。
     */
    protected function isProxyRequest(Subject $subject): bool
    {
        $target = $subject->target();

        return $target !== ''
            && $target[0] !== '/'
            && (strncasecmp($target, 'http://', 7) === 0 || strncasecmp($target, 'https://', 8) === 0);
    }

    /**
     * 把 SQL 注释（/ ** /、/*!50000 ）换成空格，让 union/ ** /select 这类写法也能匹配。
     */
    protected static function stripSqlComments(string $value): string
    {
        return str_contains($value, '/*') || str_contains($value, '*/')
            ? preg_replace('~/\*!?\d{0,6}|\*/~', ' ', $value)
            : $value;
    }

    /**
     * 把各类特征合并成一条正则。
     */
    protected static function compile(): string
    {
        $branches = [];

        foreach (static::PATTERNS as $patterns) {
            foreach ($patterns as $pattern) {
                $branches[] = '(?:'.$pattern.')';
            }
        }

        return '~'.implode('|', $branches).'~';
    }
}
