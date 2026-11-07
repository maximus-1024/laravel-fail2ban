<?php

namespace Maximus\Fail2Ban\Tests\Feature\Storage;

use Illuminate\Validation\ValidationException;
use Maximus\Fail2Ban\Contracts\SettingsRepository;
use Maximus\Fail2Ban\Tests\Support\InteractsWithFail2BanRedis;
use Maximus\Fail2Ban\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;

class SettingsRepositoryTest extends TestCase
{
    use InteractsWithFail2BanRedis;

    private SettingsRepository $settings;

    protected function setUp(): void
    {
        parent::setUp();

        $this->settings = $this->app->make(SettingsRepository::class);
    }

    #[Test]
    public function unsaved_settings_come_from_the_config_file(): void
    {
        $all = $this->settings->all();

        $this->assertSame('observe', $all['mode']);
        $this->assertSame(['action' => 'ban', 'window' => 5, 'count' => 10, 'ban' => 30], $all['rules']['not-found-scan']);
        $this->assertSame(['action' => 'ban', 'window' => 10, 'count' => 1, 'ban' => 120], $all['rules']['known-exploit']);
        $this->assertSame(array_keys(config('fail2ban.rules')), array_keys($all['rules']));
        $this->assertSame(['enabled' => true, 'factor' => 2, 'max_days' => 7, 'keep_days' => 7], $all['repeat']);
        $this->assertSame(config('fail2ban.response'), $all['response']);
        $this->assertNull($all['updated_by']);
        $this->assertNull($all['updated_at']);
        $this->assertSame($this->settings->defaults(), $all);

        // 默认值跟着配置文件走，不是写死的
        config(['fail2ban.mode' => 'block', 'fail2ban.rules.attack-pattern.count' => 7, 'fail2ban.repeat.enabled' => false]);

        $all = $this->settings->all();
        $this->assertSame('block', $all['mode']);
        $this->assertSame(7, $all['rules']['attack-pattern']['count']);
        $this->assertFalse($all['repeat']['enabled']);
    }

    #[Test]
    public function saved_values_override_defaults_and_record_who_and_when(): void
    {
        $this->travelTo(now()->setTimestamp(1762500000));

        $saved = $this->settings->save([
            'mode' => 'block',
            'rules' => ['not-found-scan' => ['count' => '15', 'action' => 'observe']],
            'repeat' => ['enabled' => false, 'factor' => 3],
            'response' => ['status' => 429, 'show_ip' => '0', 'message' => '请停止。'],
        ], 'admin');

        $this->assertSame('block', $saved['mode']);
        $this->assertSame(['action' => 'observe', 'window' => 5, 'count' => 15, 'ban' => 30], $saved['rules']['not-found-scan']);
        $this->assertSame(['enabled' => false, 'factor' => 3, 'max_days' => 7, 'keep_days' => 7], $saved['repeat']);
        $this->assertSame(429, $saved['response']['status']);
        $this->assertFalse($saved['response']['show_ip']);
        $this->assertTrue($saved['response']['show_time']);
        $this->assertSame('请停止。', $saved['response']['message']);
        $this->assertSame('admin', $saved['updated_by']);
        $this->assertSame(1762500000, $saved['updated_at']);
        $this->assertSame($saved, $this->settings->all());

        // 没保存的项仍跟着配置文件
        config(['fail2ban.rules.not-found-scan.window' => 9]);
        $this->assertSame(9, $this->settings->all()['rules']['not-found-scan']['window']);
    }

    #[Test]
    public function any_invalid_value_rejects_the_whole_change(): void
    {
        $this->settings->save(['mode' => 'block'], 'admin');
        $before = $this->redis()->hgetall('fail2ban:settings');

        $cases = [
            ['rules' => ['not-found-scan' => ['window' => 0]]],
            ['rules' => ['not-found-scan' => ['window' => 1441]]],
            ['rules' => ['not-found-scan' => ['count' => 101]]],
            ['rules' => ['not-found-scan' => ['count' => 0]]],
            ['rules' => ['not-found-scan' => ['ban' => 43201]]],
            ['rules' => ['not-found-scan' => ['ban' => 1.5]]],
            ['rules' => ['not-found-scan' => ['action' => 'block']]],
            ['rules' => ['no-such-rule' => ['count' => 3]]],
            ['repeat' => ['factor' => 1]],
            ['repeat' => ['factor' => 11]],
            ['repeat' => ['max_days' => 31]],
            ['repeat' => ['keep_days' => 0]],
            ['repeat' => ['enabled' => 'maybe']],
            ['response' => ['status' => 500]],
            ['response' => ['message' => '']],
            ['response' => ['message' => str_repeat('字', 501)]],
            ['mode' => 'ban'],
            ['enabled' => true],
            // 一项合法、一项越界：整体拒绝
            ['mode' => 'off', 'rules' => ['sensitive-path' => ['count' => 3, 'window' => 99999]]],
        ];

        foreach ($cases as $changes) {
            $this->assertNotSame([], $this->errors($changes), json_encode($changes));
            $this->assertSame($before, $this->redis()->hgetall('fail2ban:settings'), json_encode($changes));
        }

        $this->assertSame(
            ['rules.sensitive-path.window'],
            array_keys($this->errors(['mode' => 'off', 'rules' => ['sensitive-path' => ['count' => 3, 'window' => 99999]]]))
        );
    }

    #[Test]
    public function boundary_values_are_accepted(): void
    {
        $changes = [
            'mode' => 'off',
            'rules' => [
                'not-found-scan' => ['window' => 1, 'count' => 1, 'ban' => 1, 'action' => 'off'],
                'attack-pattern' => ['window' => 1440, 'count' => 100, 'ban' => 43200],
            ],
            'repeat' => ['factor' => 10, 'max_days' => 30, 'keep_days' => 1],
            'response' => ['status' => 404],
        ];

        $saved = $this->settings->save($changes, 'admin');

        $this->assertSame(['action' => 'ban', 'window' => 1440, 'count' => 100, 'ban' => 43200], $saved['rules']['attack-pattern']);
        $this->assertSame(404, $saved['response']['status']);
    }

    #[Test]
    public function the_count_limit_follows_hits_max(): void
    {
        config(['fail2ban.hits_max' => 20]);

        $this->assertSame([1, 20], $this->settings->limits()['count']);
        $this->assertNotSame([], $this->errors(['rules' => ['not-found-scan' => ['count' => 21]]]));
        $this->assertSame([], $this->errors(['rules' => ['not-found-scan' => ['count' => 20]]]));
    }

    #[Test]
    public function corrupted_stored_values_fall_back_to_defaults(): void
    {
        $this->redis()->hmset('fail2ban:settings', [
            'mode' => 'chaos',
            'rules.not-found-scan.count' => '9999',
            'rules.not-found-scan.ban' => '45',
        ]);

        $all = $this->settings->all();

        $this->assertSame('observe', $all['mode']);
        $this->assertSame(10, $all['rules']['not-found-scan']['count']);
        $this->assertSame(45, $all['rules']['not-found-scan']['ban']);
    }

    /**
     * 保存一组改动，返回校验错误；通过（已保存）时返回空数组。
     */
    private function errors(array $changes): array
    {
        try {
            $this->settings->save($changes, 'tester');

            return [];
        } catch (ValidationException $e) {
            return $e->errors();
        }
    }
}
