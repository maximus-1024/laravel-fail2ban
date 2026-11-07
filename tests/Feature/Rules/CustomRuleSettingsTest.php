<?php

namespace Maximus\Fail2Ban\Tests\Feature\Rules;

use Illuminate\Validation\ValidationException;
use Maximus\Fail2Ban\Contracts\SettingsRepository;
use Maximus\Fail2Ban\Tests\Feature\Rules\Fixtures\PortalLoginFailure;
use Maximus\Fail2Ban\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;

/**
 * 登记的自定义规则能在设置里保存与校验（连真实的测试 Redis）。
 *
 * 设置层按 config('fail2ban.rules') 的键生成可保存的设置项，自定义规则写进这份配置就自动有了
 * 动作、时间范围、出现次数、封禁时长四项，不用改 RedisSettingsRepository。
 */
class CustomRuleSettingsTest extends TestCase
{
    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);

        $app['config']->set('fail2ban.rules.login-failure', [
            'class' => PortalLoginFailure::class,
            'action' => 'observe', 'window' => 10, 'count' => 5, 'ban' => 60,
        ]);
    }

    #[Test]
    public function custom_rule_settings_can_be_saved_and_read_back(): void
    {
        $settings = app(SettingsRepository::class);

        $this->assertSame(['action' => 'observe', 'window' => 10, 'count' => 5, 'ban' => 60], $settings->all()['rules']['login-failure']);

        $saved = $settings->save(['rules' => ['login-failure' => ['action' => 'ban', 'count' => 3, 'ban' => 120]]], 'tester');

        $this->assertSame(['action' => 'ban', 'window' => 10, 'count' => 3, 'ban' => 120], $saved['rules']['login-failure']);
        $this->assertSame(['action' => 'ban', 'window' => 10, 'count' => 3, 'ban' => 120], $settings->all()['rules']['login-failure']);
        $this->assertSame('ban', $settings->all()['rules']['not-found-scan']['action'], '内置规则不受影响');
    }

    #[Test]
    public function invalid_custom_rule_settings_are_rejected_as_a_whole(): void
    {
        $settings = app(SettingsRepository::class);

        foreach ([
            'rules.login-failure.window' => ['count' => 3, 'window' => 0],
            'rules.login-failure.action' => ['action' => 'nope'],
            'rules.login-failure.class' => ['class' => 'X'],     // 类名不是可保存的设置项
        ] as $field => $changes) {
            try {
                $settings->save(['rules' => ['login-failure' => $changes]], 'tester');
                $this->fail("{$field} 应被拒绝");
            } catch (ValidationException $e) {
                $this->assertArrayHasKey($field, $e->errors());
            }
        }

        $this->assertSame(5, $settings->all()['rules']['login-failure']['count'], '整体拒绝，原值不变');
    }
}
