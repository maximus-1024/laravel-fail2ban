<?php

namespace Maximus\Fail2Ban\Tests\Feature\Storage;

use Illuminate\Validation\ValidationException;
use Maximus\Fail2Ban\Contracts\AllowlistRepository;
use Maximus\Fail2Ban\Contracts\BanRepository;
use Maximus\Fail2Ban\Tests\Support\InteractsWithFail2BanRedis;
use Maximus\Fail2Ban\Tests\TestCase;
use Maximus\Fail2Ban\Visitor;
use PHPUnit\Framework\Attributes\Test;

class AllowlistRepositoryTest extends TestCase
{
    use InteractsWithFail2BanRedis;

    private AllowlistRepository $allow;

    protected function setUp(): void
    {
        parent::setUp();

        $this->allow = $this->app->make(AllowlistRepository::class);
    }

    #[Test]
    public function builtin_ranges_match_ipv4_and_ipv6(): void
    {
        $this->assertSame(['entry' => '10.0.0.0/8', 'source' => 'private'], $this->allow->match('10.1.2.3'));
        $this->assertSame(['entry' => '127.0.0.0/8', 'source' => 'loopback'], $this->allow->match('127.0.0.1'));
        $this->assertSame(['entry' => '::1/128', 'source' => 'loopback'], $this->allow->match('::1'));
        $this->assertSame(['entry' => '104.16.0.0/13', 'source' => 'cloudflare'], $this->allow->match('104.18.1.1'));
        $this->assertSame(['entry' => '2606:4700::/32', 'source' => 'cloudflare'], $this->allow->match('2606:4700:10::6816:1'));
        $this->assertSame(['entry' => '10.0.0.0/8', 'source' => 'private'], $this->allow->match('::ffff:10.1.2.3'));

        $this->assertNull($this->allow->match('203.0.113.47'));
        $this->assertNull($this->allow->match('2001:db8::1'));
        $this->assertNull($this->allow->match('not-an-ip'));
    }

    #[Test]
    public function extra_entries_from_config_are_builtin(): void
    {
        config(['fail2ban.allowlist.extra' => ['198.51.100.7']]);

        $this->assertSame(['entry' => '198.51.100.7', 'source' => 'extra'], $this->allow->match('198.51.100.7'));
        $this->assertContains(['entry' => '198.51.100.7', 'label' => '配置文件', 'source' => 'extra'], $this->allow->builtin());
    }

    #[Test]
    public function panel_entries_match_single_addresses_and_cidrs(): void
    {
        $this->allow->add('203.0.113.47', '办公室', 'admin');
        $this->allow->add('198.51.100.0/24', null, 'admin');
        $this->allow->add('2001:0DB8:0000:0000:0000:0000:0000:0001', null, 'admin');
        $this->allow->add('2001:db8:aaaa::/48', null, 'admin');

        $this->assertNotNull($this->allow->match('203.0.113.47'));
        $this->assertNull($this->allow->match('203.0.113.48'));
        $this->assertNotNull($this->allow->match('198.51.100.200'));
        $this->assertNull($this->allow->match('198.51.101.1'));
        $this->assertNotNull($this->allow->match('2001:db8::1'));
        $this->assertNull($this->allow->match('2001:db8::2'));
        $this->assertNotNull($this->allow->match('2001:db8:aaaa:1::99'));
        $this->assertNull($this->allow->match('2001:db8:aaab::1'));

        // 访客键按网段首地址判断（手动封禁就是这么查的）
        $this->assertNotNull($this->allow->match(Visitor::address(Visitor::key('2001:db8:aaaa:5::1'))));
        $this->assertNull($this->allow->match(Visitor::key('2001:db8:aaaa:5::1')), '只接受 IP，不接受访客键');
        $this->assertSame(['entry' => '2001:db8::1', 'source' => 'panel'], $this->allow->match('2001:db8::1'));
    }

    #[Test]
    public function entries_are_normalized_listed_and_removed(): void
    {
        $this->travelTo(now()->setTimestamp(1762500000));
        $added = $this->allow->add(' 2001:0db8::0001 ', '服务器', 'admin');
        $this->travelTo(now()->setTimestamp(1762500100));
        $this->allow->add('198.51.100.0/24', '', 'bob');

        $this->assertSame(['entry' => '2001:db8::1', 'note' => '服务器', 'added_by' => 'admin', 'added_at' => 1762500000], $added);
        $this->assertSame([
            ['entry' => '2001:db8::1', 'note' => '服务器', 'added_by' => 'admin', 'added_at' => 1762500000],
            ['entry' => '198.51.100.0/24', 'note' => null, 'added_by' => 'bob', 'added_at' => 1762500100],
        ], $this->allow->entries());

        $this->assertTrue($this->allow->remove('2001:db8:0::1'));
        $this->assertFalse($this->allow->remove('2001:db8::1'));
        $this->assertFalse($this->allow->remove('garbage'));
        $this->assertNull($this->allow->match('2001:db8::1'));
        $this->assertCount(1, $this->allow->entries());
    }

    #[Test]
    public function invalid_entries_are_rejected_with_a_validation_error(): void
    {
        foreach (['abc', '203.0.113.0/33', '2001:db8::/129', '203.0.113.0/x', ''] as $bad) {
            try {
                $this->allow->add($bad, null, 'admin');
                $this->fail("Accepted [{$bad}].");
            } catch (ValidationException $e) {
                $this->assertArrayHasKey('entry', $e->errors());
            }
        }

        $this->assertSame([], $this->allow->entries());
    }

    #[Test]
    public function allowlisting_a_banned_visitor_can_be_followed_by_unban(): void
    {
        $bans = $this->app->make(BanRepository::class);
        $this->recordHit('not-found-scan', '203.0.113.47', '/a', window: 5);
        $bans->ban('203.0.113.47', ['incident' => 'BAN-20261107-AAAAAA', 'rule' => 'not-found-scan'], 30,
            ['enabled' => true, 'factor' => 2, 'max_days' => 7, 'keep_days' => 7]);

        $this->allow->add('203.0.113.0/24', null, 'admin');
        $bans->unban(Visitor::key('203.0.113.47'));

        $this->assertNotNull($this->allow->match('203.0.113.47'));
        $this->assertNull($bans->find('203.0.113.47'));
        $this->assertFalse($this->redis()->zscore('fail2ban:bans', '203.0.113.47'));
        $this->assertSame([], $bans->all());
        $this->assertSame(0, $this->redis()->exists('fail2ban:repeat:203.0.113.47'));
    }
}
