<?php

namespace Maximus\Fail2Ban\Tests\Feature\Panel;

use Orchestra\Testbench\Attributes\DefineEnvironment;
use PHPUnit\Framework\Attributes\Test;

/**
 * 面板可以限定域名（照 Horizon 的 domain），默认不限定。
 */
class PanelDomainTest extends PanelTestCase
{
    protected function useDomain($app): void
    {
        $app['config']->set('fail2ban.panel.domain', 'ops.example.com');
    }

    #[Test]
    #[DefineEnvironment('useDomain')]
    public function the_panel_only_answers_on_the_configured_domain(): void
    {
        $this->getJson('http://ops.example.com/fail2ban/api/overview')->assertOk();
        $this->get('http://ops.example.com/fail2ban')->assertOk();

        $this->getJson('http://api.example.com/fail2ban/api/overview')->assertNotFound();
        $this->get('http://api.example.com/fail2ban')->assertNotFound();
    }

    #[Test]
    public function by_default_any_domain_works(): void
    {
        $this->assertNull(config('fail2ban.panel.domain'));

        $this->getJson('http://api.example.com/fail2ban/api/overview')->assertOk();
        $this->getJson('http://ops.example.com/fail2ban/api/overview')->assertOk();
    }
}
