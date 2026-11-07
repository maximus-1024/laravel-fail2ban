<?php

namespace Maximus\Fail2Ban\Tests\Feature\Panel;

use Illuminate\Support\Facades\Gate;
use Maximus\Fail2Ban\Contracts\AuditRepository;
use Maximus\Fail2Ban\Contracts\BanRepository;
use Maximus\Fail2Ban\Contracts\IncidentRepository;
use Maximus\Fail2Ban\Fail2Ban;
use Maximus\Fail2Ban\Tests\TestCase;

/**
 * 面板与命令测试的共用部分：默认已授权、操作人是 admin；造数据直接走存储层。
 */
abstract class PanelTestCase extends TestCase
{
    /**
     * 是否把授权 viewFail2Ban 放开（测默认授权的类关掉它）。
     */
    protected bool $openGate = true;

    protected function setUp(): void
    {
        parent::setUp();

        if ($this->openGate) {
            Gate::define('viewFail2Ban', fn ($user = null) => true);
        }

        Fail2Ban::actorUsing(fn ($request) => $request ? 'admin' : null);
    }

    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);

        // web 中间件组要加密 Cookie，宿主程序都有 APP_KEY。
        $app['config']->set('app.key', 'base64:'.base64_encode(str_repeat('k', 32)));
    }

    protected function api(string $path = ''): string
    {
        return '/fail2ban/api'.$path;
    }

    /**
     * 造一次自动封禁（规则命中 → 封禁 → 攻击事件），与中间件的写法一致。
     */
    protected function autoBan(string $visitor, string $rule = 'sensitive-path', array $details = [], int $ruleBan = 120): array
    {
        $bans = app(BanRepository::class);
        $incidents = app(IncidentRepository::class);

        foreach (['/.env', '/.git/config', '/backup.zip'] as $path) {
            $this->recordHit($rule, $visitor, $path);
        }

        $this->recordHit('scanner-agent', $visitor);

        $ban = $bans->ban($visitor, $details + [
            'incident' => $incidents->nextId(),
            'rule' => $rule,
            'ip' => $visitor,
            'region' => '荷兰',
            'user_agent' => 'Mozilla/5.0 zgrab/0.x',
        ], $ruleBan, ['enabled' => true, 'factor' => 2, 'max_days' => 7, 'keep_days' => 7]);

        $incidents->record(['id' => $ban['incident'], 'disposition' => 'banned', 'time' => $ban['banned_at']] + $ban);

        return $ban;
    }

    /**
     * 最新的一条操作日志（存储形状）。
     */
    protected function lastAudit(): ?array
    {
        return app(AuditRepository::class)->paginate(null, 1, 1)['data'][0] ?? null;
    }

    protected function auditCount(): int
    {
        return app(AuditRepository::class)->paginate()['total'];
    }

    /**
     * 断言一个数组的键与类型恰好如约定：'string'、'int'、'bool'、'array'、'list'，前面加 ? 表示可为 null。
     */
    protected function assertShape(array $shape, mixed $actual, string $where = ''): void
    {
        $this->assertIsArray($actual, $where);
        $this->assertEqualsCanonicalizing(array_keys($shape), array_keys($actual), "字段不一致 {$where}");

        foreach ($shape as $key => $type) {
            $value = $actual[$key];
            $nullable = str_starts_with($type, '?');
            $type = ltrim($type, '?');

            if ($value === null) {
                $this->assertTrue($nullable, "{$where}.{$key} 不应为 null");

                continue;
            }

            match ($type) {
                'string' => $this->assertIsString($value, "{$where}.{$key}"),
                'int' => $this->assertIsInt($value, "{$where}.{$key}"),
                'bool' => $this->assertIsBool($value, "{$where}.{$key}"),
                'array' => $this->assertIsArray($value, "{$where}.{$key}"),
                'list' => $this->assertTrue(is_array($value) && array_is_list($value), "{$where}.{$key} 应为数组"),
                'time' => $this->assertMatchesRegularExpression('/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{2}:\d{2}$/', $value, "{$where}.{$key} 应为 ISO 8601"),
            };
        }
    }

    protected function incidentShape(): array
    {
        return [
            'id' => 'string', 'time' => 'time', 'visitor' => 'string', 'region' => '?string',
            'rule' => '?array', 'source' => 'string', 'count' => '?int', 'disposition' => 'string',
            'observe' => 'bool', 'operator' => '?string', 'note' => '?string',
        ];
    }

    protected function banShape(): array
    {
        return [
            'visitor' => 'string', 'visitor_note' => '?string', 'region' => '?string', 'rule' => '?array',
            'source' => 'string', 'reason' => 'string', 'banned_at' => 'time', 'unban_at' => 'time',
            'remaining_seconds' => 'int', 'total_seconds' => 'int', 'blocked' => 'int', 'offense' => '?int',
            'incident_id' => 'string', 'operator' => '?string', 'note' => '?string',
        ];
    }
}
