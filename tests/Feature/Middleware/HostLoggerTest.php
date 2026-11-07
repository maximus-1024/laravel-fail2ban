<?php

namespace Maximus\Fail2Ban\Tests\Feature\Middleware;

use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Log;
use Maximus\Fail2Ban\Events\IpBanned;
use Maximus\Fail2Ban\Inspector;
use PHPUnit\Framework\Attributes\Test;
use RuntimeException;

/**
 * 宿主把 log 绑定换成了没实现 Psr\Log\LoggerInterface 的包装类（有的应用的日志装饰器就是这样），
 * 封禁流程照常工作；收尾阶段吞掉异常时记的日志带上异常类与消息。
 */
class HostLoggerTest extends MiddlewareTestCase
{
    /**
     * 宿主的日志包装：只靠 __call 转发，不实现 PSR-3。
     */
    private function useNonPsrLogger(): object
    {
        $logger = new class($this->app->make('log'))
        {
            public array $calls = [];

            public function __construct(private object $log)
            {
            }

            public function __call($method, $parameters)
            {
                $this->calls[] = [$method, $parameters[0] ?? null];

                return $this->log->{$method}(...$parameters);
            }
        };

        $this->app->instance('log', $logger);
        Log::clearResolvedInstance('log');

        return $logger;
    }

    #[Test]
    public function the_ban_flow_works_when_the_log_binding_is_not_a_psr_logger(): void
    {
        Event::fake([IpBanned::class]);
        $logger = $this->useNonPsrLogger();
        $this->setMode('block');

        $this->api('/_ignition/execute-solution')->assertNotFound();

        $this->assertNotNull($this->ban());
        Event::assertDispatchedTimes(IpBanned::class, 1);
        $this->api('/ok')->assertForbidden();

        // 白名单段里的警告也经由宿主的 log 绑定写出
        $this->api('/_ignition/execute-solution', [], '10.0.0.8')->assertNotFound();
        $this->assertContains('warning', array_column($logger->calls, 0));
        $this->assertNotContains('error', array_column($logger->calls, 0), json_encode($logger->calls, JSON_UNESCAPED_UNICODE));
    }

    #[Test]
    public function a_swallowed_terminate_error_is_logged_with_its_class_and_message(): void
    {
        Log::spy();
        $this->setMode('block');

        $this->app->instance(Inspector::class, new class([]) extends Inspector
        {
            public function inspect($request, $response, array $actions): array
            {
                throw new RuntimeException('规则坏了');
            }
        });

        $this->api('/ok')->assertOk();

        Log::shouldHaveReceived('error')->once()->withArgs(function ($message, $context = []) {
            return str_contains($message, RuntimeException::class)
                && str_contains($message, '规则坏了')
                && ($context['exception'] ?? null) instanceof RuntimeException;
        });
    }
}
