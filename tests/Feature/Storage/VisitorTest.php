<?php

namespace Maximus\Fail2Ban\Tests\Feature\Storage;

use InvalidArgumentException;
use Maximus\Fail2Ban\Visitor;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

class VisitorTest extends TestCase
{
    #[Test]
    public function ipv4_is_kept_as_is(): void
    {
        $this->assertSame('203.0.113.47', Visitor::key('203.0.113.47'));
        $this->assertSame('203.0.113.47', Visitor::key(' 203.0.113.47 '));
    }

    #[Test]
    public function ipv6_is_reduced_to_its_64_bit_network(): void
    {
        $this->assertSame('2001:db8:4c2:91::/64', Visitor::key('2001:db8:4c2:91:a:b:c:d'));
        $this->assertSame('2001:db8:4c2:91::/64', Visitor::key('2001:0DB8:04c2:0091:ffff:ffff:ffff:ffff'));
        $this->assertSame('2001:db8::/64', Visitor::key('2001:db8::1'));
        $this->assertSame('::/64', Visitor::key('::1'));
    }

    #[Test]
    public function addresses_in_the_same_ipv6_64_share_one_key(): void
    {
        $this->assertSame(Visitor::key('2001:db8:1:2::1'), Visitor::key('2001:db8:1:2:dead:beef:0:9'));
        $this->assertNotSame(Visitor::key('2001:db8:1:2::1'), Visitor::key('2001:db8:1:3::1'));
    }

    #[Test]
    public function an_existing_key_is_accepted_and_normalized(): void
    {
        $this->assertSame('2001:db8:4c2:91::/64', Visitor::key('2001:db8:4c2:91::/64'));
        $this->assertSame('2001:db8:4c2:91::/64', Visitor::key('2001:0db8:04c2:0091:0:0:0:0/64'));
    }

    #[Test]
    public function ipv4_mapped_ipv6_is_treated_as_ipv4(): void
    {
        $this->assertSame('203.0.113.47', Visitor::key('::ffff:203.0.113.47'));
    }

    #[Test]
    public function invalid_input_is_rejected(): void
    {
        foreach (['', 'abc', '999.1.1.1', '203.0.113.0/24', '2001:db8::/48', '2001:db8::/64x'] as $bad) {
            try {
                Visitor::key($bad);
                $this->fail("Accepted [{$bad}].");
            } catch (InvalidArgumentException) {
            }
        }

        $this->expectException(InvalidArgumentException::class);

        Visitor::key('not-an-ip');
    }

    #[Test]
    public function address_strips_the_prefix_of_an_ipv6_key(): void
    {
        $this->assertSame('2001:db8::', Visitor::address('2001:db8::/64'));
        $this->assertSame('203.0.113.47', Visitor::address('203.0.113.47'));
    }
}
