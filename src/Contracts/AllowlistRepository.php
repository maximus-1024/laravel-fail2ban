<?php

namespace Maximus\Fail2Ban\Contracts;

/**
 * 白名单 NEVER_BAN：配置里的内置段，加面板添加的条目（fail2ban:allow）。
 *
 * 条目是单个 IP 或 CIDR，IPv4、IPv6 都可以。
 */
interface AllowlistRepository
{
    /**
     * 一个 IP 匹配到的白名单条目；没有匹配（或不是合法的 IP）时为 null。匹配语义见 Visitor::covers()。
     *
     * 先查内置段（不访问 Redis），再查面板条目。source 用来区分命中的是哪一类，
     * 封禁流程据此在命中内置段（内网段、回环、Cloudflare 段）时记警告。
     *
     * @return array{entry: string, source: 'private'|'loopback'|'cloudflare'|'extra'|'panel'}|null
     */
    public function match(string $ip): ?array;

    /**
     * 内置段（只读）：配置里的 private、loopback、cloudflare、extra。
     *
     * @return list<array{entry: string, label: string, source: string}>
     */
    public function builtin(): array;

    /**
     * 面板添加的条目，按添加时间升序。
     *
     * @return list<array{entry: string, note: ?string, added_by: string, added_at: int}>
     */
    public function entries(): array;

    /**
     * 添加（或覆盖同一条目的备注）。条目会被规范化（IPv6 压缩写法）。
     *
     * 不负责解封：调用方随后调用 BanRepository::unban()。
     *
     * @return array{entry: string, note: ?string, added_by: string, added_at: int}
     *
     * @throws \Illuminate\Validation\ValidationException entry 不是合法的 IP 或 CIDR（错误键 entry）
     */
    public function add(string $entry, ?string $note, string $actor): array;

    /**
     * 删除一个面板条目。
     *
     * @return bool 是否真的删掉了（不存在或不合法时为 false）
     */
    public function remove(string $entry): bool;
}
