<?php

namespace Maximus\Fail2Ban\Rules;

use Illuminate\Http\Request;
use Maximus\Fail2Ban\Contracts\Rule;
use Maximus\Fail2Ban\Rules\Concerns\UsesPatternList;
use Maximus\Fail2Ban\Rules\Support\Subject;
use Symfony\Component\HttpFoundation\Response;

/**
 * 扫描器特征：浏览器标识匹配已知安全扫描器清单。不看状态码，每次请求都算。
 *
 * curl、Guzzle、okhttp、python-requests 这类通用库不在清单里，空标识也不算。
 * 清单见 resources/rules/scanner-agents.txt；宿主可在 fail2ban.lists.scanner-agent 里追加或排除条目。
 */
class ScannerAgent implements Rule
{
    use UsesPatternList;

    public function id(): string
    {
        return 'scanner-agent';
    }

    public function name(): string
    {
        return '扫描器特征';
    }

    public function description(): string
    {
        return '浏览器标识是已知的扫描工具（如 sqlmap、Nikto、Nuclei、Nmap）时，每次请求都记一次；curl、Guzzle、okhttp 等通用库和空标识不算。';
    }

    public function isPathRule(): bool
    {
        return false;
    }

    public function matches(Request $request, Response $response): bool
    {
        $agent = Subject::of($request)->userAgent();

        return $agent !== '' && preg_match($this->compiled()['regex'], $agent) === 1;
    }

    public function key(Request $request): ?string
    {
        return null;
    }

    public function countMode(): string
    {
        return self::COUNT_EACH;
    }

    /**
     * 把清单编成一条正则：字面量分支，首尾是字母数字的条目在那一侧加「不紧挨字母数字」的断言。
     *
     * 条目按「首、尾是否字母数字」分成至多四组，每组共用一对断言：
     * (?<![a-z0-9])(?:arachni|nikto|…)(?![a-z0-9])。与每个条目各带断言的写法匹配结果相同，
     * 但 PCRE 能从字面量分支推出起始字符，不必在标识的每个位置都把七十多个分支试一遍（实测快约八倍）。
     *
     * @return array{regex: string}
     */
    public static function compile(array $entries): array
    {
        $kinds = [];

        foreach ($entries as $entry) {
            $entry = strtolower($entry);
            $kind = (ctype_alnum($entry[0]) ? '(?<![a-z0-9])' : '').'|'.(ctype_alnum($entry[-1]) ? '(?![a-z0-9])' : '');

            $kinds[$kind][$entry] = preg_quote($entry, '~');
        }

        $branches = [];

        foreach ($kinds as $kind => $quoted) {
            [$before, $after] = explode('|', $kind);

            $branches[] = $before.'(?:'.implode('|', $quoted).')'.$after;
        }

        return ['regex' => $branches ? '~'.implode('|', $branches).'~' : '~(?!)~'];
    }

    protected static function file(): string
    {
        return dirname(__DIR__, 2).'/resources/rules/scanner-agents.txt';
    }
}
