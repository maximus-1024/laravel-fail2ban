<?php

namespace Maximus\Fail2Ban\Tests\Feature\Panel;

use Maximus\Fail2Ban\Fail2Ban;
use PHPUnit\Framework\Attributes\Test;

/**
 * 操作日志接口：面板的每个改动接口和三个命令都各留下一条操作日志，带操作人与 via。
 */
class AuditTest extends PanelTestCase
{
    #[Test]
    public function every_panel_mutation_leaves_exactly_one_audit_entry_i17(): void
    {
        $this->autoBan('203.0.113.47');

        $steps = [
            'ban' => fn () => $this->postJson($this->api('/bans'), ['ip' => '198.51.100.23', 'minutes' => 30, 'note' => '人工'])->assertCreated(),
            'unban' => fn () => $this->deleteJson($this->api('/bans?visitor=203.0.113.47'))->assertNoContent(),
            'allow_add' => fn () => $this->postJson($this->api('/allowlist'), ['entry' => '192.0.2.5', 'note' => '测试环境'])->assertCreated(),
            'allow_remove' => fn () => $this->deleteJson($this->api('/allowlist?entry=192.0.2.5'))->assertNoContent(),
            'settings' => fn () => $this->putJson($this->api('/settings'), ['repeat' => ['factor' => 3]])->assertOk(),
            'mode' => fn () => $this->putJson($this->api('/settings'), ['mode' => 'block'])->assertOk(),
        ];

        foreach ($steps as $action => $step) {
            Fail2Ban::actorUsing(fn () => "op-{$action}");
            $before = $this->auditCount();

            $step();

            $this->assertSame($before + 1, $this->auditCount(), "{$action} 应恰好留下一条操作日志");

            $entry = $this->getJson($this->api('/audit?per_page=1'))->json('data.0');
            $this->assertSame($action, $entry['action']);
            $this->assertSame("op-{$action}", $entry['operator']);
            $this->assertSame('panel', $entry['via']);
        }
    }

    #[Test]
    public function the_list_has_the_agreed_shape_pagination_and_filter(): void
    {
        $this->postJson($this->api('/bans'), ['ip' => '198.51.100.23', 'minutes' => 30, 'note' => '<script>x</script>'])->assertCreated();
        $this->deleteJson($this->api('/bans?visitor=198.51.100.23'))->assertNoContent();
        $this->putJson($this->api('/settings'), ['mode' => 'block'])->assertOk();
        $this->artisan('fail2ban:mode', ['mode' => 'observe'])->assertSuccessful();

        $json = $this->getJson($this->api('/audit'))->assertOk()->json();

        $this->assertSame(['data', 'total', 'page', 'per_page', 'history_limit'], array_keys($json));
        $this->assertSame([4, 1, 20, 500], [$json['total'], $json['page'], $json['per_page'], $json['history_limit']]);

        foreach ($json['data'] as $i => $entry) {
            $this->assertShape(['time' => 'time', 'operator' => 'string', 'action' => 'string', 'target' => 'string', 'detail' => 'string', 'via' => 'string'], $entry, "data.{$i}");
        }

        $this->assertSame(['mode', 'mode', 'unban', 'ban'], array_column($json['data'], 'action'));
        $this->assertSame(['console', 'panel', 'panel', 'panel'], array_column($json['data'], 'via'));
        $this->assertSame(['console', 'admin', 'admin', 'admin'], array_column($json['data'], 'operator'));
        $this->assertSame('由「拦截」改为「观察」', $json['data'][0]['detail']);
        $this->assertSame('198.51.100.23', $json['data'][3]['target']);
        $this->assertSame('封 30 分钟。备注：<script>x</script>', $json['data'][3]['detail']);

        $this->assertSame(['ban'], $this->getJson($this->api('/audit?action=ban'))->json('data.*.action'));

        $page = $this->getJson($this->api('/audit?page=2&per_page=3'))->json();
        $this->assertSame([4, 2, 3], [$page['total'], $page['page'], $page['per_page']]);
        $this->assertSame(['ban'], array_column($page['data'], 'action'));
    }

    #[Test]
    public function the_history_limit_follows_config(): void
    {
        config(['fail2ban.history_limit' => 3]);

        foreach (range(1, 5) as $i) {
            $this->putJson($this->api('/settings'), ['repeat' => ['factor' => 2 + $i]])->assertOk();
        }

        $this->getJson($this->api('/audit'))->assertJsonPath('total', 3)->assertJsonPath('history_limit', 3);
        $this->getJson($this->api('/incidents'))->assertJsonPath('history_limit', 3);
    }
}
