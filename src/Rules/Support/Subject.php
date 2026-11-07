<?php

namespace Maximus\Fail2Ban\Rules\Support;

use Illuminate\Http\Request;
use WeakMap;

/**
 * 一个请求里规则要看的那几样东西，统一做好解码与归一化，每个请求只算一次。
 *
 * 防绕过的口径（五条规则共用）：
 *  - 每样东西都同时检查「原样」和「逐层解码」后的结果，最多解码 DECODE_MAX 层，
 *    所以单层、双层、三层 URL 编码都能看穿；四层及以上不再解（正常请求不会这样编码，
 *    攻击方这样做时服务端也不会解到那一层）。
 *  - 一律转小写（大小写混写无效），去掉空字节（%00 截断无效）。
 *  - 「垫长」不能成为绕过手段：路径与查询串看前 URI_MAX 字节，覆盖 Cloudflare 允许的
 *    地址长度，更长的地址过不了 Cloudflare（nginx 默认的请求行上限也只有 8 KB），超出的部分不看。
 *    查询串不再先整串截断再拆参数，而是拆成一个个参数各自检查，每个参数整段检查（不按参数截断：
 *    按参数截断会留下「在同一个参数里垫长」的绕过）；参数个数最多 PARAMS_MAX 个，其余的合成最后一段
 *    整体检查，不丢。总量受 URI_MAX 约束，所以最坏的耗时有上限；攻击特征对每一段先做不带正则的预筛，
 *    垫进去的长参数不进正则。
 *  - 请求头（浏览器标识、来源页）只取前 CHECK_MAX 字节。
 *  - 查询串按 & 拆成一个个参数，参数名与参数值分开检查，避免两个正常参数拼在一起被误判。
 */
final class Subject
{
    /**
     * 请求头（浏览器标识、来源页）参与匹配的最大字节数。
     */
    public const CHECK_MAX = 4096;

    /**
     * 路径与查询串参与匹配的最大字节数。Cloudflare 文档对地址长度给了两个数（连接限制页 16 KB，
     * 414 错误页 32 KB），取大的那个，经 Cloudflare 来的地址都能整段看到。
     */
    public const URI_MAX = 32768;

    /**
     * 查询串最多单独检查的参数个数；之后的参数合成一段整体检查。
     */
    public const PARAMS_MAX = 100;

    /**
     * 最多解码的层数。
     */
    public const DECODE_MAX = 3;

    /**
     * 去重键的最大长度，超过就改用摘要。
     */
    public const KEY_MAX = 255;

    /**
     * @var \WeakMap<Request, self>|null
     */
    private static ?WeakMap $cache = null;

    private ?array $pathLayers = null;

    private ?array $pathVariants = null;

    private ?array $pathCandidates = null;

    private ?array $queryVariants = null;

    private ?array $queryPieces = null;

    /**
     * 读过的请求头原值（HeaderBag::get() 每次都要规范化头名，几条规则都看浏览器标识）。
     *
     * @var array<string, string>
     */
    private array $headers = [];

    private function __construct(
        private readonly Request $request,
        private readonly string $path,
        private readonly string $query,
        private readonly string $target,
    ) {
    }

    /**
     * 取这个请求的检查对象（同一个请求对象只解析一次）。
     */
    public static function of(Request $request): self
    {
        self::$cache ??= new WeakMap;

        if (! isset(self::$cache[$request])) {
            // 先读原始请求目标：Symfony 第一次算 getRequestUri() 时会把代理式的
            // "http://host/path" 改写成 "/path"，之后就看不到了。
            $target = (string) $request->server->get('REQUEST_URI', '');
            $uri = $request->getRequestUri();
            $at = strpos($uri, '?');

            self::$cache[$request] = new self(
                $request,
                $at === false ? $uri : substr($uri, 0, $at),
                $at === false ? '' : substr($uri, $at + 1),
                $target,
            );
        }

        return self::$cache[$request];
    }

    /**
     * 原样的路径（还带着百分号编码，不含查询参数）。
     */
    public function path(): string
    {
        return $this->path === '' ? '/' : $this->path;
    }

    /**
     * 原样的查询串（不含问号）。
     */
    public function query(): string
    {
        return $this->query;
    }

    /**
     * 原样的「路径加查询参数」。
     */
    public function uri(): string
    {
        return $this->query === '' ? $this->path() : $this->path().'?'.$this->query;
    }

    /**
     * 请求行上原始的请求目标（REQUEST_URI）。代理式请求是一个完整网址。
     *
     * 注意：如果在这之前已经有代码调用过 getRequestUri()（路由、CORS 中间件都会），
     * Symfony 已经把它改写成只剩路径，这里就看不到完整网址了。
     */
    public function target(): string
    {
        return $this->target;
    }

    /**
     * 请求行上真实的方法，不受 _method 与 X-HTTP-Method-Override 影响。
     */
    public function method(): string
    {
        return strtoupper($this->request->getRealMethod());
    }

    /**
     * 浏览器标识的匹配形式：小写、去空字节、截断。没有时为空字符串。
     */
    public function userAgent(): string
    {
        return self::clean($this->header('User-Agent'));
    }

    /**
     * 请求头的原值，没有时为空字符串。
     */
    public function header(string $name): string
    {
        return $this->headers[$name] ??= (string) $this->request->headers->get($name, '');
    }

    /**
     * 路径的原样与各个解码层次（只清理，不做路径归一化），供攻击特征匹配。
     *
     * @return list<string>
     */
    public function pathLayers(): array
    {
        return $this->pathLayers ??= self::decodeLayers($this->path(), false, self::URI_MAX);
    }

    /**
     * 路径的各个解码层次，供地址类规则匹配。
     *
     * 每一层都做路径归一化：反斜杠改正斜杠、连续斜杠合并、去掉 "/./"、去掉末尾斜杠。
     *
     * @return list<string>
     */
    public function pathVariants(): array
    {
        return $this->pathVariants ??= array_values(array_unique(array_map(
            self::normalizePath(...),
            $this->pathLayers(),
        )));
    }

    /**
     * 地址清单的匹配对象：每个解码层次的路径，以及它末尾补一个斜杠的形式。
     *
     * 补斜杠是为了让 "*\/.git/*" 这样的条目同时命中 "/.git" 和 "/.git/config"。
     *
     * @return list<string>
     */
    public function pathCandidates(): array
    {
        if ($this->pathCandidates !== null) {
            return $this->pathCandidates;
        }

        $candidates = [];

        foreach ($this->pathVariants() as $path) {
            $candidates[] = $path;

            if (! str_ends_with($path, '/')) {
                $candidates[] = $path.'/';
            }
        }

        return $this->pathCandidates = $candidates;
    }

    /**
     * 整个查询串的各个解码层次。
     *
     * @return list<string>
     */
    public function queryVariants(): array
    {
        return $this->queryVariants ??= $this->query === ''
            ? []
            : self::decodeLayers($this->query, true, self::URI_MAX);
    }

    /**
     * 查询串拆成参数后，每个参数名与参数值的各个解码层次，去重后平铺。
     *
     * 查询串取前 URI_MAX 字节；前 PARAMS_MAX 个参数各自拆开，其余的（第 PARAMS_MAX+1 个起）合成最后一段，
     * 照样拆一次名与值、整体解码检查。每一段都整段检查，不按参数截断。
     *
     * @return list<string>
     */
    public function queryPieces(): array
    {
        if ($this->queryPieces !== null) {
            return $this->queryPieces;
        }

        $pieces = [];
        $query = substr($this->query, 0, self::URI_MAX);

        foreach (explode('&', $query, self::PARAMS_MAX + 1) as $pair) {
            if ($pair === '') {
                continue;
            }

            foreach (explode('=', $pair, 2) as $part) {
                if ($part !== '') {
                    foreach (self::decodeLayers($part, true, self::URI_MAX) as $layer) {
                        $pieces[$layer] = true;
                    }
                }
            }
        }

        return $this->queryPieces = array_keys($pieces);
    }

    /**
     * 原样与逐层解码的结果，都已清理（小写、去空字节、截断到 $max 字节）。
     *
     * @return list<string>
     */
    public static function decodeLayers(string $value, bool $plusIsSpace, int $max = self::CHECK_MAX): array
    {
        $value = substr($value, 0, $max);
        $layers = [self::clean($value, $max)];

        for ($i = 0; $i < self::DECODE_MAX; $i++) {
            $decoded = $plusIsSpace ? urldecode($value) : rawurldecode($value);

            if ($decoded === $value) {
                break;
            }

            $layers[] = self::clean($decoded, $max);
            $value = $decoded;
        }

        return array_values(array_unique($layers));
    }

    /**
     * 小写、去空字节、截断到 $max 字节（默认 CHECK_MAX）。
     */
    public static function clean(string $value, int $max = self::CHECK_MAX): string
    {
        return strtolower(str_replace("\0", '', substr($value, 0, $max)));
    }

    /**
     * 路径归一化：反斜杠改正斜杠、连续斜杠合并、去掉 "/./"、去掉末尾斜杠（根路径除外）。
     */
    public static function normalizePath(string $path): string
    {
        $path = preg_replace('~/{2,}~', '/', str_replace('\\', '/', $path));

        while (str_contains($path, '/./')) {
            $path = str_replace('/./', '/', $path);
        }

        if (str_ends_with($path, '/.')) {
            $path = substr($path, 0, -1);
        }

        $path = rtrim($path, '/');

        return $path === '' ? '/' : ($path[0] === '/' ? $path : '/'.$path);
    }

    /**
     * 去重键用的摘要：不把原文存进 Redis 时用。
     */
    public static function digest(string $value): string
    {
        return 'sha1:'.sha1($value);
    }

    /**
     * 去重键：保证是合法 UTF-8（非法字节换成 "?"，存储与 JSON 都不会出错），太长就取摘要。
     */
    public static function key(string $value): string
    {
        if (strlen($value) > self::KEY_MAX) {
            return self::digest($value);
        }

        return mb_check_encoding($value, 'UTF-8') ? $value : mb_scrub($value, 'UTF-8');
    }
}
