<?php

namespace Maximus\Fail2Ban\Tests\Feature\Rules;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

/**
 * 地址类规则看响应状态的口径（走完整的规则入口）：
 *  - 恶意明确的地址不看状态码：宿主把一切异常渲染成「HTTP 200 加业务码」时也要算；
 *  - 宿主可能真有的页面（运维面板、后台入口）只在响应不是成功（不在 200–399）时算；
 *  - 404 扫描仍只认 404，且只在另外两条地址类规则都没命中时算。
 */
class ResponseStatusTest extends RuleTestCase
{
    public static function maliciousWhenHostAlwaysAnswers200(): array
    {
        return [
            'Laravel 日志（命中 storage/{path} 路由，签名校验失败被渲染成 200）' => ['/storage/logs/laravel.log', 'sensitive-path'],
            'Laravel 日志目录' => ['/storage/logs/', 'sensitive-path'],
            '会话文件' => ['/storage/framework/sessions/abc', 'sensitive-path'],
            '.env' => ['/.env', 'sensitive-path'],
            '.env 编码' => ['/%2eenv', 'sensitive-path'],
            '.git' => ['/.git/config', 'sensitive-path'],
            '数据库导出' => ['/backup.sql', 'sensitive-path'],
            '打包备份' => ['/www.zip', 'sensitive-path'],
            '后门脚本' => ['/shell.php', 'sensitive-path'],
            'WordPress 登录（.php）' => ['/wp-login.php', 'sensitive-path'],
            'Ignition 利用地址' => ['/_ignition/execute-solution', 'known-exploit'],
            'PHPUnit 利用地址' => ['/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php', 'known-exploit'],
            'PHP-CGI 利用地址' => ['/cgi-bin/php5', 'known-exploit'],
            'WordPress 批量接口' => ['/wp-json/batch/v1', 'known-exploit'],
            'vBulletin' => ['/ajax/render/widget_php', 'known-exploit'],
        ];
    }

    #[Test]
    #[DataProvider('maliciousWhenHostAlwaysAnswers200')]
    public function malicious_paths_count_when_the_host_answers_200(string $uri, string $rule): void
    {
        $this->assertSame([$rule], $this->hitIds($this->makeRequest('GET', $uri), $this->hostJson(404, '资源不存在')));
        $this->assertSame([$rule], $this->hitIds($this->makeRequest('GET', $uri), $this->hostJson(401, '签名错误')));
        $this->assertSame([$rule], $this->hitIds($this->makeRequest('GET', $uri), $this->response(404)), '404 时仍只记这一条，不再记 404 扫描');
    }

    public static function hostPages(): array
    {
        return [
            ['/horizon'], ['/horizon/dashboard'], ['/horizon/api/stats'], ['/telescope/requests'], ['/pulse'],
            ['/nova/resources/users'], ['/log-viewer'], ['/_debugbar/open'], ['/phpmyadmin/'], ['/wp-admin/'],
        ];
    }

    #[Test]
    #[DataProvider('hostPages')]
    public function an_admin_opening_a_host_panel_successfully_does_not_count(string $uri): void
    {
        $admin = ['User-Agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36'];

        foreach ([200, 204, 302, 304] as $status) {
            $this->assertSame([], $this->hitIds($this->makeRequest('GET', $uri, $admin), $this->response($status)), "$uri $status");
        }
    }

    #[Test]
    #[DataProvider('hostPages')]
    public function a_host_panel_counts_when_the_response_is_not_successful(string $uri): void
    {
        foreach ([401, 403, 404, 405, 419, 500, 503] as $status) {
            $this->assertSame(['sensitive-path'], $this->hitIds($this->makeRequest('GET', $uri), $this->response($status)), "$uri $status");
        }
    }

    #[Test]
    public function the_fail2ban_panel_itself_is_not_listed(): void
    {
        foreach (['/fail2ban', '/fail2ban/', '/fail2ban/bans', '/fail2ban/api/bans', '/fail2ban/api/settings', '/fail2ban/api/incidents/BAN-20261107-7K2M9Q'] as $uri) {
            foreach ([200, 401, 403, 419, 422, 500] as $status) {
                $this->assertSame([], $this->hitIds($this->makeRequest('GET', $uri), $this->response($status)), "$uri $status");
            }

            // 真的不存在时只是普通的 404 扫描
            $this->assertSame(['not-found-scan'], $this->hitIds($this->makeRequest('GET', $uri), $this->response(404)), "$uri 404");
        }
    }

    #[Test]
    public function not_found_scan_still_only_counts_404(): void
    {
        foreach ([200, 401, 403, 405, 410, 500] as $status) {
            $this->assertSame([], $this->hitIds($this->makeRequest('GET', '/v1/transactions/pays'), $this->response($status)), (string) $status);
        }

        $this->assertSame(['not-found-scan'], $this->hitIds($this->makeRequest('GET', '/v1/transactions/pays'), $this->response(404)));
    }

    #[Test]
    public function the_front_controller_is_only_counted_when_not_successful(): void
    {
        $this->assertSame([], $this->hitIds($this->makeRequest('GET', '/index.php'), $this->response(200)));
        $this->assertSame([], $this->hitIds($this->makeRequest('GET', '/index.php?locale=zh'), $this->response(200)));
        $this->assertSame(['sensitive-path'], $this->hitIds($this->makeRequest('GET', '/index.php'), $this->response(404)));
    }
}
