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
        foreach ([404, 200, 403] as $status) {
            $this->assertFalse((new SensitivePath)->matches($this->makeRequest('GET', $path), $this->response($status)), "$path $status");
        }
    }

    public static function successfulStatuses(): array
    {
        return ['200' => [200], '204' => [204], '301' => [301], '302' => [302], '304' => [304]];
    }

    public static function failedStatuses(): array
    {
        return ['401' => [401], '403' => [403], '404' => [404], '405' => [405], '419' => [419], '500' => [500], '503' => [503]];
    }

    /**
     * [any-status] 分段的样例：每段至少一个，不看状态码。
     */
    private const MALICIOUS = [
        '/.env', '/.env.production', '/docker-compose.yml', '/composer.json', '/phpinfo', '/id_rsa',   // 环境与配置文件
        '/.git', '/.git/config', '/cvs/root',                                                          // 版本库目录
        '/backup.sql', '/www.zip', '/debug.log', '/index.php~',                                       // 备份与数据库导出
        '/shell.php', '/login.aspx', '/a.pl', '/wp-login.php', '/cgi-bin/test.cgi',                    // 后门与脚本后缀
        '/storage/logs/laravel.log', '/storage/logs', '/storage/framework/sessions/x', '/storage/sessions/x',
        '/bootstrap/cache/config.php', '/artisan',                                                    // Laravel 日志、缓存与会话
    ];

    /**
     * [non-success] 分段的样例：每段至少一个，只在响应不是成功时算。
     */
    private const HOST_PAGES = [
        '/phpmyadmin/', '/pma/', '/adminer', '/wp-admin/', '/administrator/', '/actuator/health', '/cgi-bin/luci', // 后台入口
        '/horizon', '/horizon/dashboard', '/telescope/requests', '/pulse', '/_ignition/health-check', '/_debugbar/open',
        '/clockwork/app', '/log-viewer', '/nova/resources', '/laravel-filemanager', '/_profiler/empty/search/results', // 面板
        '/GponForm/diag_Form', '/HNAP1/', '/wls-wsat/CoordinatorPortType', '/boaform/admin/formLogin',          // 其它平台
    ];

    #[Test]
    #[DataProvider('successfulStatuses')]
    #[DataProvider('failedStatuses')]
    public function malicious_paths_match_regardless_of_status(int $status): void
    {
        $rule = new SensitivePath;

        // 例如宿主把一切渲染成 HTTP 200：/storage/logs/laravel.log 命中 Laravel 自带的 storage/{path} 路由，
        // 签名校验失败被渲染成 200，也要算。
        foreach (self::MALICIOUS as $path) {
            $this->assertTrue($rule->matches($this->makeRequest('GET', $path), $this->response($status)), "$path $status");
        }
    }

    #[Test]
    #[DataProvider('successfulStatuses')]
    public function host_pages_that_open_successfully_do_not_match(int $status): void
    {
        $rule = new SensitivePath;

        // 宿主装了 Horizon 时管理员打开 /horizon 是 200（或跳转登录的 302），不能算。
        foreach (self::HOST_PAGES as $path) {
            $this->assertFalse($rule->matches($this->makeRequest('GET', $path), $this->response($status)), "$path $status");
        }
    }

    #[Test]
    #[DataProvider('failedStatuses')]
    public function host_pages_match_when_the_response_is_not_successful(int $status): void
    {
        $rule = new SensitivePath;

        // 没登录、没权限、不存在、出错都算：管理员自己不会一直授权不过。
        foreach (self::HOST_PAGES as $path) {
            $this->assertTrue($rule->matches($this->makeRequest('GET', $path), $this->response($status)), "$path $status");
        }
    }

    #[Test]
    public function the_front_controller_is_a_real_page(): void
    {
        $rule = new SensitivePath;

        // /index.php 符合 "*.php"，但它是宿主的入口脚本：成功时不算，不是成功时照常算。
        foreach (['/index.php', '/index.php/', '/INDEX.PHP'] as $path) {
            foreach ([200, 302] as $status) {
                $this->assertFalse($rule->matches($this->makeRequest('GET', $path), $this->response($status)), "$path $status");
            }

            $this->assertTrue($rule->matches($this->makeRequest('GET', $path), $this->response(404)), "$path 404");
        }

        // 只有入口脚本本身例外，别的 .php 照样不看状态码
        foreach (['/index.php.bak', '/public/index.php', '/x/index.php', '/index2.php'] as $path) {
            $this->assertTrue($rule->matches($this->makeRequest('GET', $path), $this->response(200)), $path);
        }

        // 入口脚本按 SCRIPT_NAME 认：放在子目录下时是 /app/index.php
        $request = $this->makeRequest('GET', '/app/index.php');
        $request->server->set('SCRIPT_NAME', '/app/index.php');
        $this->assertFalse($rule->matches($request, $this->response(200)));
    }

    /**
     * 2026-11-07 第二次补充的 [any-status] 条目：每条一个样例，宿主回 200 也算。
     */
    public static function addedAnyStatus(): array
    {
        return [
            '.git-credentials' => ['/.git-credentials'], '.kube' => ['/.kube/config'], 'terraform.tfstate' => ['/terraform.tfstate'],
            'sftp-config.json' => ['/sftp-config.json'], 'ftpsync.settings' => ['/ftpsync.settings'], 'sftp.json' => ['/sftp.json'],
            'service-account-credentials.json' => ['/service-account-credentials.json'],
            'serviceaccountcredentials.json' => ['/serviceAccountCredentials.json'],
            '.netrc' => ['/.netrc'], '.pgpass' => ['/.pgpass'], '.my.cnf' => ['/.my.cnf'], '.pypirc' => ['/.pypirc'],
            '.psql_history' => ['/.psql_history'], '.sqlite_history' => ['/.sqlite_history'], '.rediscli_history' => ['/.rediscli_history'],
            '.node_repl_history' => ['/.node_repl_history'], '@fs' => ['/@fs/etc/passwd'], '@id' => ['/@id/x'],
        ];
    }

    #[Test]
    #[DataProvider('addedAnyStatus')]
    public function added_any_status_entries_match_regardless_of_status(string $path): void
    {
        foreach ([200, 302, 404] as $status) {
            $this->assertTrue((new SensitivePath)->matches($this->makeRequest('GET', $path), $this->response($status)), "$path $status");
        }
    }

    /**
     * 2026-11-07 第二次补充的 [non-success] 条目（以及从「环境与配置文件」挪来的前端运行时配置）：每条一个样例。
     */
    public static function addedNonSuccess(): array
    {
        return [
            '_profiler 带前端控制器' => ['/app_dev.php/_profiler/empty/search/results'], 'livewire' => ['/livewire/update'],
            'symfony.lock' => ['/symfony.lock'], 'phpstan.neon' => ['/phpstan.neon'], 'psalm.xml' => ['/psalm.xml'],
            'phpcs.xml' => ['/phpcs.xml.dist'], 'webpack.mix.js' => ['/webpack.mix.js'], 'vite.config.js' => ['/vite.config.js'],
            'opcache-status' => ['/php-opcache-status/'], 'auth.json' => ['/backup/auth.json'], '.php_history' => ['/.php_history'],
            'appsettings.json' => ['/appsettings.json'], 'appsettings.production.json' => ['/appsettings.Production.json'],
            'google-services.json' => ['/android/app/google-services.json'], 'credentials.json' => ['/credentials.json'],
            '.travis.yml' => ['/.travis.yml'], 'bitbucket-pipelines.yml' => ['/bitbucket-pipelines.yml'],
            'node_modules' => ['/node_modules/.bin/x'], 'roundcube' => ['/roundcube/'], 'webmail' => ['/webmail'], 'horde' => ['/horde/login'],
            'jolokia' => ['/api/jolokia/read'], 'nginx_status' => ['/nginx_status'], 'pprof' => ['/debug/pprof/heap'],
            'debug/default/view' => ['/frontend/web/debug/default/view'], 'app/etc/local.xml' => ['/app/etc/local.xml'],
            'awstats' => ['/awstats/data'],
            'env.js' => ['/env.js'], 'env.json' => ['/env.json'], 'env.dev.js' => ['/env.dev.js'], 'env.test.js' => ['/env.test.js'],
            'env.production.js' => ['/env.production.js'],
        ];
    }

    #[Test]
    #[DataProvider('addedNonSuccess')]
    public function added_non_success_entries_need_an_unsuccessful_response(string $path): void
    {
        $rule = new SensitivePath;

        foreach ([200, 304] as $status) {
            $this->assertFalse($rule->matches($this->makeRequest('GET', $path), $this->response($status)), "$path $status");
        }

        foreach ([403, 404, 500] as $status) {
            $this->assertTrue($rule->matches($this->makeRequest('GET', $path), $this->response($status)), "$path $status");
        }
    }

    public static function addedNearMisses(): array
    {
        return [
            ['/kube/config'], ['/my.cnf'], ['/sftp-config.yaml'], ['/terraform'], ['/auth'], ['/auth/login'], ['/credentials'],
            ['/appsettings'], ['/mail/inbox'], ['/live/wire'], ['/debug'], ['/nginx_status/extra'], ['/@vite/client'], ['/fs/x'],
            ['/environment.js'], ['/app/env'], ['/merchant/auth/login'], ['/v1/credentials/rotate'], ['/node_module/x'],
        ];
    }

    #[Test]
    #[DataProvider('addedNearMisses')]
    public function added_entries_do_not_catch_near_misses(string $path): void
    {
        foreach ([200, 403, 404] as $status) {
            $this->assertFalse((new SensitivePath)->matches($this->makeRequest('GET', $path), $this->response($status)), "$path $status");
        }
    }

    /**
     * 2026-11-10 起任何层级都算：扫描器在宿主的子前缀下探测，原先只认根目录的条目漏掉了这些请求。
     *
     * @return array<string, array{string, int}>
     */
    public static function nestedProbes(): array
    {
        return [
            'ignition 健康检查' => ['/portal/_ignition/health-check', 404],
            'ignition 多层前缀' => ['/api/v1/_ignition/scripts/x', 404],
            'debugbar' => ['/portal/_debugbar/open', 404],
            'clockwork' => ['/portal/clockwork/app', 404],
            'clockwork 不带斜杠' => ['/portal/clockwork', 403],
            '__clockwork' => ['/portal/__clockwork/latest', 404],
            '子目录 .env' => ['/api/.env', 200],
            '子目录 .git' => ['/portal/.git/config', 200],
            'vite @fs 带 base' => ['/build/@fs/etc/passwd', 200],
            'vite @id 带 base' => ['/portal/@id/x', 200],
        ];
    }

    #[Test]
    #[DataProvider('nestedProbes')]
    public function converted_entries_match_under_a_sub_prefix(string $path, int $status): void
    {
        $this->assertTrue((new SensitivePath)->matches($this->makeRequest('GET', $path), $this->response($status)), "$path $status");
    }

    #[Test]
    public function converted_non_success_entries_still_need_an_unsuccessful_response_under_a_sub_prefix(): void
    {
        foreach (['/portal/_ignition/health-check', '/portal/_debugbar/open', '/portal/clockwork/app'] as $path) {
            $this->assertFalse((new SensitivePath)->matches($this->makeRequest('GET', $path), $this->response(200)), $path);
        }
    }

    /**
     * 只在根目录的 8 条（普通英文词，或包把前端文件发布在 public/vendor 下）：子前缀下不算，根目录照旧算。
     *
     * @return array<string, array{string}>
     */
    public static function rootOnlyUnderSubPrefix(): array
    {
        return [
            'artisan' => ['/products/artisan'], 'artisan 子路径' => ['/api/artisan'],
            'horizon' => ['/api/v1/horizon'], 'horizon 子路径' => ['/portal/horizon/dashboard'],
            'pulse' => ['/api/pulse'], 'pulse 子路径' => ['/health/pulse/check'],
            'nova' => ['/api/nova/orders'], 'nova 不带斜杠' => ['/merchant/nova'],
            'telescope' => ['/portal/telescope/requests'], 'telescope 发布的前端文件' => ['/vendor/telescope/app.js'],
            'log-viewer' => ['/portal/log-viewer'], 'log-viewer 发布的前端文件' => ['/vendor/log-viewer/app.js'],
            'laravel-filemanager' => ['/portal/laravel-filemanager/upload'],
            'laravel-filemanager 发布的前端文件' => ['/vendor/laravel-filemanager/js/script.js'],
            'livewire' => ['/portal/livewire/update'], 'livewire 发布的前端文件' => ['/vendor/livewire/livewire.js'],
        ];
    }

    #[Test]
    #[DataProvider('rootOnlyUnderSubPrefix')]
    public function root_only_entries_do_not_match_under_a_sub_prefix(string $path): void
    {
        foreach ([200, 403, 404] as $status) {
            $this->assertFalse((new SensitivePath)->matches($this->makeRequest('GET', $path), $this->response($status)), "$path $status");
        }
    }

    #[Test]
    public function root_only_entries_still_match_at_the_root(): void
    {
        $rule = new SensitivePath;

        $this->assertTrue($rule->matches($this->makeRequest('GET', '/artisan'), $this->response(200)));

        foreach (['/telescope/requests', '/horizon/dashboard', '/pulse', '/log-viewer', '/nova/resources', '/laravel-filemanager', '/livewire/update'] as $path) {
            $this->assertTrue($rule->matches($this->makeRequest('GET', $path), $this->response(404)), $path);
            $this->assertFalse($rule->matches($this->makeRequest('GET', $path), $this->response(200)), $path);
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
