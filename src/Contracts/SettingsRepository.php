<?php

namespace Maximus\Fail2Ban\Contracts;

/**
 * 运行设置：面板保存的值盖在配置文件默认值上。
 *
 * 「设置」的形状（all()、defaults()、save() 的返回值；键名与 config/fail2ban.php 一致）：
 *
 *     [
 *         'mode' => 'off'|'observe'|'block',
 *         'rules' => [
 *             'not-found-scan' => ['action' => 'ban'|'observe'|'off', 'window' => int, 'count' => int, 'ban' => int],
 *             ...                                   // 配置里的每条规则；window、ban 单位分钟
 *         ],
 *         'repeat' => ['enabled' => bool, 'factor' => int, 'max_days' => int, 'keep_days' => int],
 *         'response' => ['status' => int, 'message' => string, 'show_ip' => bool, 'show_incident' => bool, 'show_time' => bool],
 *         'updated_by' => ?string,
 *         'updated_at' => ?int,
 *     ]
 */
interface SettingsRepository
{
    /**
     * 当前生效的设置。没保存过的项取配置文件默认值。
     */
    public function all(): array;

    /**
     * 配置文件里的默认值（不访问 Redis）。
     */
    public function defaults(): array;

    /**
     * 把 fail2ban:settings 哈希的原始内容盖到默认值上（不访问 Redis）。
     *
     * 给需要把设置和别的读取放进同一个管道的调用方用（BanRepository::lookup()）。
     * 原始值不合法（例如被手工改坏）的项按默认值。
     *
     * @param  array<string, string>  $stored
     */
    public function resolve(array $stored): array;

    /**
     * 校验并保存一组改动，记下操作人与时间。任何一项不合法则整体拒绝、原值不变。
     * 这是数值范围与可选值的唯一一处校验。
     *
     * $changes 是设置形状的任意子集，例如 ['rules' => ['not-found-scan' => ['count' => 5]]]。
     * 未知的项也算错误。
     *
     * @return array 保存后的设置
     *
     * @throws \Illuminate\Validation\ValidationException 校验失败，错误键是点号路径（如 rules.not-found-scan.count）
     */
    public function save(array $changes, string $actor): array;

    /**
     * 可填范围，供面板显示。message 是提示文字的字数范围。
     *
     * @return array{window: array{int, int}, count: array{int, int}, ban: array{int, int}, factor: array{int, int}, max_days: array{int, int}, keep_days: array{int, int}, statuses: list<int>, message: array{int, int}}
     */
    public function limits(): array;
}
