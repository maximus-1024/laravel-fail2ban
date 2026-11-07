<?php

namespace Maximus\Fail2Ban\Tests\Feature\Rules;

use Maximus\Fail2Ban\Rules\SensitivePath;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

class SensitivePathTest extends RuleTestCase
{
    public static function sensitivePaths(): array
    {
        return [
            // 环境与配置
            ['/.env'], ['/.env.production'], ['/.env.bak'], ['/.env~'], ['/public/.env'], ['/api/.env.local'],
            ['/production.env'], ['/.aws/credentials'], ['/.circleci/config.yml'], ['/docker-compose.yml'], ['/.htaccess'],
            ['/id_rsa'], ['/.ssh/id_rsa.pub'], ['/.DS_Store'], ['/composer.json'], ['/vendor/composer/installed.json'],
            ['/phpinfo'], ['/server-status'], ['/web.config'], ['/.bash_history'],
            // 版本库
            ['/.git'], ['/.git/'], ['/.git/config'], ['/.git/HEAD'], ['/.svn/entries'], ['/.hg/store/data'],
            // 备份与导出
            ['/backup.sql'], ['/db.sql.gz'], ['/www.zip'], ['/api.example.com.tar.gz'], ['/site.rar'], ['/data.bak'],
            ['/index.php.old'], ['/dump.sqlite'], ['/debug.log'],
            // 后台入口
            ['/phpmyadmin/'], ['/phpMyAdmin/index.php'], ['/phpmyadmin4.8.5/'], ['/pma/'], ['/adminer'],
            ['/wp-admin/install.php'], ['/wp-login.php'], ['/wp-content/plugins/x/readme.txt'], ['/administrator/'],
            ['/manager/html'], ['/solr/admin/'], ['/actuator/env'], ['/cgi-bin/test'], ['/nacos/'],
            // 后门与脚本后缀
            ['/shell.php'], ['/c99.php'], ['/wso2.8.5.php'], ['/upload/x.phtml'], ['/default.asp'], ['/login.aspx'],
            ['/index.jsp'], ['/test.cgi'], ['/login.action'], ['/a.pl'],
            // Laravel 专项
            ['/storage/logs/laravel.log'], ['/storage/logs/'], ['/telescope'], ['/telescope/requests'], ['/horizon'],
            ['/horizon/dashboard'], ['/_ignition/health-check'], ['/_ignition/scripts/x'], ['/_debugbar/open'],
            ['/clockwork/app'], ['/log-viewer'], ['/artisan'], ['/pulse'],
            // 2026-11-07 新加：Laravel 与 PHP 专项、具体的 yml 文件名、shell 历史
            ['/.phpunit.result.cache'], ['/phpunit.xml'], ['/.composer-auth.json'], ['/.composer/composer.json'],
            ['/.php_cs.cache'], ['/nova/resources'], ['/laravel-filemanager'], ['/storage/sessions/x'],
            ['/storage/framework/sessions/'], ['/storage/oauth-private.key'], ['/_profiler/empty/search/results'],
            ['/.zsh_history'], ['/.mysql_history'], ['/docker-compose.prod.yml'], ['/parameters.yml'], ['/.gitlab-ci.yml'],
            ['/serverless.yaml'],
        ];
    }

    #[Test]
    #[DataProvider('sensitivePaths')]
    public function sensitive_paths_match_on_404(string $path): void
    {
        $this->assertTrue((new SensitivePath)->matches($this->makeRequest('GET', $path), $this->response(404)), $path);
    }

    public static function evasions(): array
    {
        return [
            '大小写混写' => ['/.ENV'],
            '大小写混写二' => ['/.Git/Config'],
            '单层编码' => ['/%2eenv'],
            '单层编码斜杠' => ['/.git%2fconfig'],
            '双层编码' => ['/%252eenv'],
            '三层编码' => ['/%25252eenv'],
            '空字节' => ['/.env%00'],
            '空字节夹在中间' => ['/.e%00nv'],
            '反斜杠' => ['/static%5c.env'],
            '连续斜杠' => ['//.git//HEAD'],
            '点段' => ['/./.env'],
            '末尾点段' => ['/.git/.'],
            '加查询参数' => ['/.env?x=1'],
        ];
    }

    #[Test]
    #[DataProvider('evasions')]
    public function encoding_tricks_do_not_evade(string $path): void
    {
        $this->assertTrue((new SensitivePath)->matches($this->makeRequest('GET', $path), $this->response(404)), $path);
    }

    public static function ordinaryNotFound(): array
    {
        return [
            ['/v1/transactions/pay/queryy'], ['/v1/prepay/abc/def'], ['/favicon.ico'], ['/robots.txt'],
            ['/apple-touch-icon.png'], ['/sitemap.xml'], ['/crossdomain.xml'], ['/proxy.pac'], ['/wpad.dat'],
            ['/.well-known/security.txt'], ['/.well-known/acme-challenge/abc'], ['/.well-known/apple-app-site-association'],
            ['/autodiscover/autodiscover.xml'], ['/swagger.json'], ['/swagger-ui.html'], ['/api-docs'], ['/v2/api-docs'],
            ['/admin'], ['/manager'], ['/environment'], ['/env'], ['/merchant/deposit-orders/123/notify'],
            ['/merchant/common/downloads/withdrawals/import-template'], ['/portal/deposit-orders/123/detail'],
            ['/storage/images/logo.png'], ['/logs'], ['/.github/workflows'], ['/'], ['/index.html'],
            ['/v1/transactions/pay%2Fquery'], ['/wpad'], ['/horizontal'], ['/telescopes'],
            // 2026-11-07 收紧 *.yml、*.yaml、*_history 后不再命中：商户找接口描述、猜接口名
            ['/openapi.yaml'], ['/swagger.yaml'], ['/api.yaml'], ['/openapi.yml'], ['/v1/transactions/pay_history'],
            ['/order_history'],
            // Telescope、Horizon 发布的前端文件：没发布时运维打开面板会连着 404，不能算（所以没加 /vendor/*）
            ['/vendor/telescope/app.js'], ['/vendor/horizon/app.css'],
        ];
    }

    #[Test]
    #[DataProvider('ordinaryNotFound')]
    public function ordinary_missing_paths_do_not_match(string $path): void
    {
        $this->assertFalse((new SensitivePath)->matches($this->makeRequest('GET', $path), $this->response(404)), $path);
    }

    public static function nonNotFoundStatuses(): array
    {
        return [[200], [302], [401], [403], [405], [500]];
    }

    #[Test]
    #[DataProvider('nonNotFoundStatuses')]
    public function sensitive_paths_need_a_404(int $status): void
    {
        $rule = new SensitivePath;

        // 宿主装了 Horizon 时 /horizon 返回 200 或 403，不能算。
        foreach (['/.env', '/horizon', '/telescope/requests', '/index.php', '/.git/config'] as $path) {
            $this->assertFalse($rule->matches($this->makeRequest('GET', $path), $this->response($status)), "$path $status");
        }
    }

    #[Test]
    public function key_is_the_path_without_query(): void
    {
        $rule = new SensitivePath;

        $this->assertSame('/.env', $rule->key($this->makeRequest('GET', '/.env?a=1')));
        $this->assertSame('/.env', $rule->key($this->makeRequest('GET', '/.env?b=2')));
        $this->assertSame('/%2eenv', $rule->key($this->makeRequest('GET', '/%2eenv')));
    }
}
