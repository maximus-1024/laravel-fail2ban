<?php

namespace Maximus\Fail2Ban\Tests\Feature\Panel;

use Maximus\Fail2Ban\Tests\Feature\Rules\Fixtures\LegacyApiPath;
use Maximus\Fail2Ban\Tests\Feature\Rules\Fixtures\PortalLoginFailure;
use Orchestra\Testbench\Attributes\DefineEnvironment;
use PHPUnit\Framework\Attributes\Test;

/**
 * 设置接口里规则按配置文件的书写顺序列出（不是检测顺序），
 * 自定义规则跟在后面；总览的规则分布仍按命中数降序。
 */
class SettingsRuleOrderTest extends PanelTestCase
{
    protected function withCustomRules($app): void
    {
        // 自定义的地址类规则在检测顺序里排在 404 扫描之前，在设置里仍按书写顺序排在最后
        $app['config']->set('fail2ban.rules.legacy-api', ['class' => LegacyApiPath::class, 'action' => 'observe', 'window' => 30, 'count' => 3, 'ban' => 240]);
        $app['config']->set('fail2ban.rules.login-failure', ['class' => PortalLoginFailure::class, 'action' => 'observe', 'window' => 10, 'count' => 5, 'ban' => 60]);
    }

    #[Test]
    public function settings_list_rules_in_config_order(): void
    {
        $this->assertSame(
            ['not-found-scan', 'sensitive-path', 'scanner-agent', 'attack-pattern', 'known-exploit'],
            array_column($this->getJson($this->api('/settings'))->assertOk()->json('rules'), 'id'),
        );
    }

    #[Test]
    #[DefineEnvironment('withCustomRules')]
    public function custom_rules_follow_the_builtin_ones(): void
    {
        $this->assertSame(
            ['not-found-scan', 'sensitive-path', 'scanner-agent', 'attack-pattern', 'known-exploit', 'legacy-api', 'login-failure'],
            array_column($this->getJson($this->api('/settings'))->json('rules'), 'id'),
        );

        // PUT 返回的形状同 GET
        $this->assertSame(
            ['not-found-scan', 'sensitive-path', 'scanner-agent', 'attack-pattern', 'known-exploit', 'legacy-api', 'login-failure'],
            array_column($this->putJson($this->api('/settings'), ['mode' => 'block'])->assertOk()->json('rules'), 'id'),
        );
    }

    #[Test]
    public function the_overview_still_sorts_rules_by_hits(): void
    {
        $this->recordHit('known-exploit', '203.0.113.9');
        $this->recordHit('known-exploit', '203.0.113.9');
        $this->recordHit('scanner-agent', '203.0.113.9');

        $this->assertSame(
            ['known-exploit', 'scanner-agent'],
            array_slice(array_column($this->getJson($this->api('/overview'))->json('rules'), 'id'), 0, 2),
        );
    }
}
