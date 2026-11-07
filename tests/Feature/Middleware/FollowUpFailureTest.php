<?php

namespace Maximus\Fail2Ban\Tests\Feature\Middleware;

use Illuminate\Support\Facades\Event;
use Maximus\Fail2Ban\Contracts\AuditRepository;
use Maximus\Fail2Ban\Contracts\IncidentRepository;
use Maximus\Fail2Ban\Contracts\StatsRepository;
use Maximus\Fail2Ban\Events\BanSkipped;
use Maximus\Fail2Ban\Events\IpBanned;
use Maximus\Fail2Ban\Fail2Ban;
use Maximus\Fail2Ban\Operations;
use Maximus\Fail2Ban\Repositories\RedisAuditRepository;
use Maximus\Fail2Ban\Repositories\RedisIncidentRepository;
use Maximus\Fail2Ban\Repositories\RedisStatsRepository;
use PHPUnit\Framework\Attributes\Test;
use RedisException;

/**
 * 改动（封禁、解封……）已经写进 Redis 之后，后面的几步各自兜住异常。
 *
 * 一次读超时不能把攻击事件、统计、封禁事件（告警）、操作日志全部带掉；事件的派发不依赖前面几步都成功。
 */
class FollowUpFailureTest extends MiddlewareTestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        Event::fake([IpBanned::class, BanSkipped::class]);
    }

    /**
     * 让某个存储的某个方法抛读超时。
     */
    private function failing(string $contract, string $method): void
    {
        $this->app->forgetInstance($contract);

        $this->app->singleton($contract, match ($contract) {
            IncidentRepository::class => fn ($app) => new class($app['redis'], $method) extends RedisIncidentRepository
            {
                public function __construct($redis, public string $fail)
                {
                    parent::__construct($redis);
                }

                public function record(array $incident): array
                {
                    return $this->fail === 'record' ? throw new RedisException('read error on connection') : parent::record($incident);
                }

                public function markUnbanned(string $id): bool
                {
                    return $this->fail === 'markUnbanned' ? throw new RedisException('read error on connection') : parent::markUnbanned($id);
                }
            },
            StatsRepository::class => fn ($app) => new class($app['redis']) extends RedisStatsRepository
            {
                public function incrementBans(): void
                {
                    throw new RedisException('read error on connection');
                }
            },
            AuditRepository::class => fn ($app) => new class($app['redis']) extends RedisAuditRepository
            {
                public function record(string $operator, string $action, ?string $target = null, string|array|null $detail = null, ?string $via = null): array
                {
                    throw new RedisException('read error on connection');
                }
            },
        });
    }

    #[Test]
    public function a_failing_incident_write_does_not_drop_the_stats_or_the_banned_event(): void
    {
        $this->setMode('block');
        $this->failing(IncidentRepository::class, 'record');

        $this->api('/_ignition/execute-solution')->assertNotFound();

        $this->assertNotNull($ban = $this->ban());
        $this->assertSame(1, $this->app->make(StatsRepository::class)->trend(1)[0]['bans']);

        Event::assertDispatchedTimes(IpBanned::class, 1);
        Event::assertDispatched(IpBanned::class, fn (IpBanned $e) => $e->ban['incident'] === $ban['incident']
            && $e->incident['id'] === $ban['incident']
            && $e->incident['disposition'] === 'banned');
    }

    #[Test]
    public function a_failing_stats_write_does_not_drop_the_incident_or_the_banned_event(): void
    {
        $this->setMode('block');
        $this->failing(StatsRepository::class, 'incrementBans');

        $this->api('/_ignition/execute-solution')->assertNotFound();

        $this->assertNotNull($ban = $this->ban());
        $this->assertSame($ban['incident'], $this->incidents()[0]['id']);
        Event::assertDispatchedTimes(IpBanned::class, 1);
    }

    #[Test]
    public function a_failing_incident_write_does_not_drop_the_skipped_event(): void
    {
        $this->setMode('block');
        Fail2Ban::exemptUsing(fn () => true);
        $this->failing(IncidentRepository::class, 'record');

        $this->api('/_ignition/execute-solution')->assertNotFound();

        $this->assertNull($this->ban());
        Event::assertDispatchedTimes(BanSkipped::class, 1);
        Event::assertDispatched(BanSkipped::class, fn (BanSkipped $e) => $e->incident['disposition'] === 'exempted'
            && $e->incident['rule'] === 'known-exploit');
    }

    #[Test]
    public function operations_still_write_the_audit_log_when_marking_the_incident_fails(): void
    {
        $this->bans()->banManually(self::IP, ['incident' => 'BAN-20261107-AAAAAA', 'operator' => 't'], 10);
        $this->failing(IncidentRepository::class, 'markUnbanned');

        $ban = $this->app->make(Operations::class)->unban(self::IP, 'admin', AuditRepository::VIA_PANEL);

        $this->assertSame('BAN-20261107-AAAAAA', $ban['incident']);
        $this->assertNull($this->ban());
        $this->assertSame('unban', $this->app->make(AuditRepository::class)->paginate(null, 1, 1)['data'][0]['action']);
    }

    #[Test]
    public function operations_report_success_when_only_the_audit_log_fails(): void
    {
        $this->failing(AuditRepository::class, 'record');
        $operations = $this->app->make(Operations::class);

        $ban = $operations->ban(self::IP, 60, '人工', 'admin', AuditRepository::VIA_PANEL);
        $this->assertNotNull($this->ban());
        $this->assertSame($ban['incident'], $this->incidents()[0]['id'], '攻击事件照常写入');

        $this->assertNotNull($operations->unban(self::IP, 'admin', AuditRepository::VIA_PANEL));
        $this->assertNull($this->ban());

        $this->assertSame('203.0.113.0/24', $operations->allow('203.0.113.0/24', null, 'admin', AuditRepository::VIA_PANEL)['entry']);
        $this->assertTrue($operations->disallow('203.0.113.0/24', 'admin', AuditRepository::VIA_PANEL));

        $this->assertSame('block', $operations->switchMode('block', 'admin', AuditRepository::VIA_PANEL)['mode']);
    }
}
