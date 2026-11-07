<?php

namespace Maximus\Fail2Ban\Http;

use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Foundation\Exceptions\Handler;
use Throwable;

/**
 * 面板接口请求期间的异常处理：包住宿主的异常处理，渲染一律由扩展包做，上报一律交给宿主。
 *
 * 面板前端靠 HTTP 状态码判断成败。有的宿主把所有异常渲染成「HTTP 200 加业务码」，
 * 前端会把它当成成功，所以面板接口里的任何异常都不交给宿主渲染，而是交给框架自带的默认渲染
 * （一个没有任何宿主回调的 Illuminate\Foundation\Exceptions\Handler，一律给 JSON）：
 *
 *  - 校验失败 ValidationException：422 {message, errors}
 *  - 未登录 AuthenticationException：401；无权限 AuthorizationException：403；令牌失效：419；
 *    不存在（RecordsNotFoundException、NotFoundHttpException）：404；其它 HttpException 按它自己的状态码。以上都是 {message}
 *  - 其余（服务器错误）：500 {message}。message 跟随应用的调试开关 app.debug：开着时是异常消息并附
 *    exception、file、line、trace，关着时是「Server Error」。
 *
 * 上报（report、shouldReport）交给宿主：宿主的日志与告警渠道照常收到面板接口里的异常。
 * 由 Http\Middleware\RenderPanelExceptions 在面板接口请求期间换上，请求结束换回。
 */
class PanelExceptionHandler implements ExceptionHandler
{
    /**
     * 框架默认的渲染（第一次用到时创建）。
     */
    protected ?Handler $framework = null;

    public function __construct(
        protected ExceptionHandler $host,
        protected Container $container,
    ) {
    }

    public function report(Throwable $e)
    {
        $this->host->report($e);
    }

    public function shouldReport(Throwable $e)
    {
        return $this->host->shouldReport($e);
    }

    public function render($request, Throwable $e)
    {
        $this->framework ??= (new Handler($this->container))->shouldRenderJsonWhen(fn () => true);

        return $this->framework->render($request, $e);
    }

    public function renderForConsole($output, Throwable $e)
    {
        $this->host->renderForConsole($output, $e);
    }
}
