<?php

namespace Maximus\Fail2Ban\Tests\Feature\Panel;

use Maximus\Fail2Ban\Fail2Ban;
use Orchestra\Testbench\Attributes\DefineEnvironment;
use PHPUnit\Framework\Attributes\Test;

/**
 * 外壳页面：内联脚本与样式、csrf 令牌、window.Fail2Ban，脚本在 #app 之后；
 * 面板地址下的任意子路径都返回外壳，而 /api/* 不会。
 */
class ShellTest extends PanelTestCase
{
    protected function customPath($app): void
    {
        $app['config']->set('fail2ban.panel.path', '/ops/firewall/');
    }

    #[Test]
    public function the_shell_inlines_the_compiled_panel_and_passes_the_globals(): void
    {
        $html = $this->get('/fail2ban')
            ->assertOk()
            ->assertHeader('Content-Type', 'text/html; charset=UTF-8')
            ->getContent();

        $css = file_get_contents(__DIR__.'/../../../dist/app.css');
        $js = file_get_contents(__DIR__.'/../../../dist/app.js');

        $this->assertStringContainsString('<style>'.$css.'</style>', $html);
        $this->assertStringContainsString('<script>'.$js.'</script>', $html);
        $this->assertSame(1, substr_count($html, '<div id="app"></div>'));

        $this->assertMatchesRegularExpression('/<meta name="csrf-token" content="[A-Za-z0-9]{40}">/', $html);

        // 脚本（window.Fail2Ban 与编译产物）都在 #app 之后。
        $app = strpos($html, '<div id="app">');
        $this->assertLessThan(strpos($html, 'window.Fail2Ban ='), $app);
        $this->assertLessThan(strpos($html, '<script>'.substr($js, 0, 40)), $app);
        $this->assertLessThan(strpos($html, 'window.Fail2Ban ='), strpos($html, '<style>'));

        $this->assertSame(['path' => '/fail2ban', 'api' => '/fail2ban/api', 'user' => 'admin'], $this->globals($html));
    }

    #[Test]
    public function every_sub_path_returns_the_shell_but_api_paths_do_not(): void
    {
        foreach (['/fail2ban/', '/fail2ban/bans', '/fail2ban/incidents', '/fail2ban/settings', '/fail2ban/audit', '/fail2ban/a/b/c', '/fail2ban/apis', '/fail2ban/x/api'] as $uri) {
            $this->get($uri)->assertOk()->assertSee('<div id="app"></div>', false);
        }

        foreach (['/fail2ban/api', '/fail2ban/api/', '/fail2ban/api/unknown', '/fail2ban/api/bans/extra/x/y'] as $uri) {
            $response = $this->getJson($uri);

            $this->assertContains($response->status(), [404, 405], $uri);
            $this->assertStringNotContainsString('<div id="app">', $response->getContent(), $uri);
        }
    }

    #[Test]
    #[DefineEnvironment('customPath')]
    public function the_panel_path_comes_from_config(): void
    {
        $html = $this->get('/ops/firewall/bans')->assertOk()->getContent();

        $this->assertSame(['path' => '/ops/firewall', 'api' => '/ops/firewall/api', 'user' => 'admin'], $this->globals($html));
        $this->getJson('/ops/firewall/api/overview')->assertOk();
        $this->get('/fail2ban')->assertNotFound();
    }

    #[Test]
    public function quotes_and_angle_brackets_in_the_user_cannot_break_the_page(): void
    {
        $evil = '</script><script>alert(1)</script>"\'<!-- & \\u2028';

        Fail2Ban::actorUsing(fn () => $evil);

        $html = $this->get('/fail2ban')->assertOk()->getContent();

        // 页面里只有我们自己的两个 <script>（加上编译产物字符串里本来就有的），注入的标签没有出现。
        $js = strtolower(file_get_contents(__DIR__.'/../../../dist/app.js'));
        $this->assertSame(2 + substr_count($js, '<script>'), substr_count(strtolower($html), '<script>'));
        $this->assertSame(2 + substr_count($js, '</script'), substr_count(strtolower($html), '</script'));
        $this->assertStringNotContainsString('<script>alert(1)', $html);
        $this->assertSame(substr_count($js, '<!--'), substr_count($html, '<!--'));

        // 读回来的值与原值一致。
        $this->assertSame($evil, $this->globals($html)['user']);
    }

    /**
     * 解析页面里写入的 window.Fail2Ban（Js::from 的输出是 JSON.parse('...')）。
     */
    protected function globals(string $html): array
    {
        $this->assertSame(1, preg_match("/window\\.Fail2Ban = JSON\\.parse\\('(.*?)'\\);/s", $html, $m), '找不到 window.Fail2Ban');

        // 单引号里是一个 JS 字符串字面量（只含 JSON 也认识的转义），先解出 JSON 文本，再解 JSON。
        $json = json_decode('"'.$m[1].'"', flags: JSON_THROW_ON_ERROR);

        return json_decode($json, true, flags: JSON_THROW_ON_ERROR);
    }
}
