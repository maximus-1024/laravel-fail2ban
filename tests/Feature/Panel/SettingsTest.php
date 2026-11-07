<?php

namespace Maximus\Fail2Ban\Tests\Feature\Panel;

use Maximus\Fail2Ban\Contracts\Rule;
use Maximus\Fail2Ban\Contracts\SettingsRepository;
use Maximus\Fail2Ban\Inspector;
use Illuminate\Http\Request;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\HttpFoundation\Response;

/**
 * 防护配置接口：越界整体 422、错误键是接口字段名、原值不变；保存成功后存储层读到新值。
 */
class SettingsTest extends PanelTestCase
{
    protected function settings(): array
    {
        return app(SettingsRepository::class)->all();
    }

    #[Test]
    public function get_has_the_agreed_shape(): void
    {
        $this->recordHit('sensitive-path', '203.0.113.47', target: '/.env');
        $this->recordHit('sensitive-path', '203.0.113.47', target: '/.git');
        $this->recordHit('known-exploit', '203.0.113.47', target: '/vendor/phpunit');

        $json = $this->getJson($this->api('/settings'))->assertOk()->json();

        $this->assertShape([
            'enabled' => 'bool', 'mode' => 'string', 'rules' => 'list', 'repeat' => 'array', 'response' => 'array',
            'limits' => 'array', 'updated_by' => '?string', 'updated_at' => '?time',
        ], $json, 'settings');

        $this->assertFalse($json['enabled']);
        $this->assertSame('observe', $json['mode']);
        $this->assertNull($json['updated_by']);
        $this->assertNull($json['updated_at']);

        foreach ($json['rules'] as $i => $rule) {
            $this->assertShape([
                'id' => 'string', 'name' => 'string', 'description' => 'string', 'count_mode' => 'string', 'action' => 'string',
                'window_minutes' => 'int', 'count' => 'int', 'ban_minutes' => 'int', 'hits_24h' => 'int',
            ], $rule, "rules.{$i}");
        }

        // count_mode 取规则自己的 countMode()（v10 补充）
        $this->assertSame([
            'not-found-scan' => 'distinct', 'sensitive-path' => 'distinct', 'scanner-agent' => 'each',
            'attack-pattern' => 'distinct', 'known-exploit' => 'distinct',
        ], array_column($json['rules'], 'count_mode', 'id'));

        // 规则按配置文件里的书写顺序列出（不是检测顺序）；名称与说明取规则类自己的。
        $inspector = app(Inspector::class);
        $this->assertSame(array_keys(config('fail2ban.rules')), array_column($json['rules'], 'id'));

        $rules = collect($json['rules'])->keyBy('id');
        $this->assertSame($inspector->rule('sensitive-path')->name(), $rules['sensitive-path']['name']);
        $this->assertSame($inspector->rule('sensitive-path')->description(), $rules['sensitive-path']['description']);
        $this->assertSame(['ban', 10, 3, 120, 2], [
            $rules['sensitive-path']['action'], $rules['sensitive-path']['window_minutes'],
            $rules['sensitive-path']['count'], $rules['sensitive-path']['ban_minutes'], $rules['sensitive-path']['hits_24h'],
        ]);
        $this->assertSame(1, $rules['known-exploit']['hits_24h']);
        $this->assertSame(0, $rules['not-found-scan']['hits_24h']);

        $this->assertShape(['enabled' => 'bool', 'factor' => 'int', 'max_days' => 'int', 'keep_days' => 'int'], $json['repeat'], 'repeat');
        $this->assertShape(['status' => 'int', 'message' => 'string', 'show_ip' => 'bool', 'show_incident' => 'bool', 'show_time' => 'bool'], $json['response'], 'response');

        $this->assertSame([
            'window_minutes' => [1, 1440], 'count' => [1, 100], 'ban_minutes' => [1, 43200],
            'factor' => [2, 10], 'max_days' => [1, 30], 'keep_days' => [1, 30], 'statuses' => [403, 429, 404], 'message' => [1, 500],
        ], $json['limits']);
    }

    #[Test]
    public function the_message_limit_is_the_one_saving_enforces(): void
    {
        [$min, $max] = $this->getJson($this->api('/settings'))->json('limits.message');

        $this->assertSame(1, $min);

        $this->putJson($this->api('/settings'), ['response' => ['message' => str_repeat('字', $max)]])
            ->assertOk()
            ->assertJsonPath('response.message', str_repeat('字', $max));

        $this->putJson($this->api('/settings'), ['response' => ['message' => str_repeat('字', $max + 1)]])
            ->assertUnprocessable()
            ->assertJsonValidationErrors('response.message');
    }

    #[Test]
    public function the_rule_list_follows_the_registered_rules(): void
    {
        // 规则库可扩展：宿主登记一条自定义规则并在配置里给它默认值。
        $custom = new class implements Rule
        {
            public function id(): string { return 'login-burst'; }
            public function name(): string { return '登录爆破'; }
            public function description(): string { return '自定义规则'; }
            public function isPathRule(): bool { return false; }
            public function matches(Request $request, Response $response): bool { return false; }
            public function key(Request $request): ?string { return null; }
            public function countMode(): string { return Rule::COUNT_EACH; }
        };

        config(['fail2ban.rules.login-burst' => ['class' => $custom::class, 'action' => 'observe', 'window' => 3, 'count' => 4, 'ban' => 5]]);
        $this->app->forgetInstance(Inspector::class);

        $rules = collect($this->getJson($this->api('/settings'))->json('rules'))->keyBy('id');

        $this->assertCount(6, $rules);
        $this->assertSame(['id' => 'login-burst', 'name' => '登录爆破', 'description' => '自定义规则', 'count_mode' => 'each', 'action' => 'observe',
            'window_minutes' => 3, 'count' => 4, 'ban_minutes' => 5, 'hits_24h' => 0], $rules['login-burst']);

        $this->putJson($this->api('/settings'), ['rules' => [['id' => 'login-burst', 'count' => 9]]])
            ->assertOk()
            ->assertJsonPath('rules.5.count', 9);
    }

    #[Test]
    public function saving_maps_api_fields_to_storage_and_returns_the_new_settings_i20(): void
    {
        $response = $this->putJson($this->api('/settings'), [
            'mode' => 'block',
            'rules' => [
                ['id' => 'not-found-scan', 'action' => 'observe', 'window_minutes' => 7, 'count' => 12, 'ban_minutes' => 45],
                ['id' => 'known-exploit', 'ban_minutes' => 600],
            ],
            'repeat' => ['enabled' => false, 'factor' => 3, 'max_days' => 10, 'keep_days' => 2],
            'response' => ['status' => 429, 'message' => '请稍后再试', 'show_ip' => false, 'show_incident' => true, 'show_time' => false],
        ])->assertOk();

        $stored = $this->settings();

        $this->assertSame('block', $stored['mode']);
        $this->assertSame(['action' => 'observe', 'window' => 7, 'count' => 12, 'ban' => 45], $stored['rules']['not-found-scan']);
        $this->assertSame(600, $stored['rules']['known-exploit']['ban']);
        $this->assertSame(1, $stored['rules']['known-exploit']['count'], '没提交的字段不变');
        $this->assertSame(['enabled' => false, 'factor' => 3, 'max_days' => 10, 'keep_days' => 2], $stored['repeat']);
        $this->assertSame(429, $stored['response']['status']);
        $this->assertSame('admin', $stored['updated_by']);

        // 返回的形状与 GET 一致，并且是新值
        $this->assertSame($this->getJson($this->api('/settings'))->json(), $response->json());
        $rule = collect($response->json('rules'))->firstWhere('id', 'not-found-scan');
        $this->assertSame([7, 12, 45, 'observe'], [$rule['window_minutes'], $rule['count'], $rule['ban_minutes'], $rule['action']]);
        $this->assertSame('admin', $response->json('updated_by'));
        $this->assertNotNull($response->json('updated_at'));
    }

    #[Test]
    public function out_of_range_values_are_rejected_with_api_field_names_and_nothing_changes_i20(): void
    {
        $this->putJson($this->api('/settings'), ['rules' => [['id' => 'sensitive-path', 'count' => 4]]])->assertOk();
        $before = $this->settings();

        $response = $this->putJson($this->api('/settings'), [
            'mode' => 'panic',
            'rules' => [
                ['id' => 'not-found-scan', 'window_minutes' => 30],            // 合法，但因为别的项越界也不能保存
                ['id' => 'sensitive-path', 'window_minutes' => 1441, 'count' => 101, 'ban_minutes' => 0, 'action' => 'kill'],
            ],
            'repeat' => ['factor' => 1, 'max_days' => 31, 'keep_days' => 0],
            'response' => ['status' => 500, 'message' => ''],
        ])->assertUnprocessable();

        $this->assertEqualsCanonicalizing([
            'mode',
            'rules.1.window_minutes', 'rules.1.count', 'rules.1.ban_minutes', 'rules.1.action',
            'repeat.factor', 'repeat.max_days', 'repeat.keep_days',
            'response.status', 'response.message',
        ], array_keys($response->json('errors')));
        $this->assertIsString($response->json('message'));
        $this->assertIsString($response->json('errors')['rules.1.count'][0]);

        $this->assertSame($before, $this->settings());
    }

    #[Test]
    public function malformed_rule_items_are_rejected_with_their_index(): void
    {
        $before = $this->settings();

        $this->putJson($this->api('/settings'), ['rules' => [['id' => 'not-found-scan', 'count' => 2], ['id' => 'nope', 'count' => 2]]])
            ->assertUnprocessable()->assertJsonValidationErrors(['rules.1.id']);
        $this->putJson($this->api('/settings'), ['rules' => [['count' => 2]]])
            ->assertUnprocessable()->assertJsonValidationErrors(['rules.0.id']);
        $this->putJson($this->api('/settings'), ['rules' => [['id' => 'not-found-scan', 'hits_24h' => 2]]])
            ->assertUnprocessable()->assertJsonValidationErrors(['rules.0.hits_24h']);
        $this->putJson($this->api('/settings'), ['rules' => ['not-found-scan' => ['count' => 2]]])
            ->assertUnprocessable()->assertJsonValidationErrors(['rules']);
        $this->putJson($this->api('/settings'), ['enabled' => true])
            ->assertUnprocessable()->assertJsonValidationErrors(['enabled']);
        $this->putJson($this->api('/settings'), ['repeat' => ['bogus' => 1]])
            ->assertUnprocessable()->assertJsonValidationErrors(['repeat.bogus']);

        $this->assertSame($before, $this->settings());
        $this->assertSame(0, $this->auditCount());
    }

    #[Test]
    public function saving_writes_an_audit_entry_with_old_and_new_values(): void
    {
        $this->putJson($this->api('/settings'), ['rules' => [['id' => 'not-found-scan', 'ban_minutes' => 10]]])->assertOk();
        $this->putJson($this->api('/settings'), ['rules' => [['id' => 'not-found-scan', 'ban_minutes' => 30]]])->assertOk();

        $entry = $this->lastAudit();

        $this->assertSame('settings', $entry['action']);
        $this->assertSame('admin', $entry['operator']);
        $this->assertSame('404 扫描', $entry['target']);
        $this->assertSame('panel', $entry['via']);
        $this->assertArrayNotHasKey('via', $entry['detail'], '来源是存储字段，不再塞在 detail 里');
        $this->assertSame(['rules.not-found-scan.ban' => 10], $entry['detail']['old']);
        $this->assertSame(['rules.not-found-scan.ban' => 30], $entry['detail']['new']);
        $this->assertSame('404 扫描 封禁时长由 10 分钟改为 30 分钟', $entry['detail']['text']);

        // 改模式另记一条 mode
        $this->putJson($this->api('/settings'), ['mode' => 'block'])->assertOk();
        $entry = $this->lastAudit();
        $this->assertSame('mode', $entry['action']);
        $this->assertSame('observe', $entry['detail']['old']);
        $this->assertSame('block', $entry['detail']['new']);
        $this->assertSame('由「观察」改为「拦截」，同时解除观察期间产生的 0 个自动封禁', $entry['detail']['text']);
        $this->assertSame(0, $entry['detail']['cleared']);
    }
}
