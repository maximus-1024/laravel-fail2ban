<?php

namespace Maximus\Fail2Ban\Tests\Feature\Storage;

use Illuminate\Contracts\Redis\Factory;
use Maximus\Fail2Ban\Contracts\SettingsRepository;
use Maximus\Fail2Ban\Contracts\StatsRepository;
use Maximus\Fail2Ban\Repositories\RedisBanRepository;
use Maximus\Fail2Ban\Tests\Support\InteractsWithFail2BanRedis;
use Maximus\Fail2Ban\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;

/**
 * 读封禁列表时清理名单索引，不能误删在读与清理之间刚写入的新封禁的索引项。
 */
class BanIndexCleanupTest extends TestCase
{
    use InteractsWithFail2BanRedis;

    #[Test]
    public function a_ban_written_between_the_read_and_the_cleanup_keeps_its_index_entry(): void
    {
        $visitor = '203.0.113.9';
        $repeat = ['enabled' => true, 'factor' => 2, 'max_days' => 7, 'keep_days' => 7];

        // 索引里有它、封禁键却已经没了（例如刚到期、索引还没清）
        $this->redis()->zadd('fail2ban:bans', now()->addHour()->getTimestamp(), $visitor);

        // 在 all() 读完封禁键之后、清理之前，另一个请求封了它
        $repository = new class($this->app->make(Factory::class), $this->app->make(SettingsRepository::class), $this->app->make(StatsRepository::class)) extends RedisBanRepository
        {
            public ?\Closure $afterRead = null;

            private int $calls = 0;

            protected function pipeline(callable $callback): array
            {
                $results = parent::pipeline($callback);

                if (++$this->calls === 2 && $this->afterRead) {
                    ($this->afterRead)();
                }

                return $results;
            }
        };

        $other = $this->app->make(\Maximus\Fail2Ban\Contracts\BanRepository::class);
        $repository->afterRead = fn () => $other->ban($visitor, ['incident' => 'BAN-20261107-AAAAAA', 'rule' => 'known-exploit'], 120, $repeat);

        $this->assertSame([], $repository->all(), '读的那一刻还没有封禁');

        $this->assertNotFalse($this->redis()->zscore('fail2ban:bans', $visitor), '新封禁的索引项不能被删掉');
        $this->assertSame([$visitor], array_column($other->all(), 'visitor'));
    }

    #[Test]
    public function expired_index_entries_are_still_cleaned_by_score(): void
    {
        $this->redis()->zadd('fail2ban:bans', now()->subMinute()->getTimestamp(), '203.0.113.9');

        $this->assertSame([], $this->app->make(\Maximus\Fail2Ban\Contracts\BanRepository::class)->all());
        $this->assertFalse($this->redis()->zscore('fail2ban:bans', '203.0.113.9'));
    }
}
