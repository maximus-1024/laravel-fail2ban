<?php

namespace Maximus\Fail2Ban\Http\Middleware;

use Closure;
use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Http\Request;
use Maximus\Fail2Ban\Http\PanelExceptionHandler;
use Symfony\Component\HttpFoundation\Response;

/**
 * 面板接口自己渲染自己的错误：任何异常都按面板约定的 JSON 与真实状态码返回（422、401、403、419、404、
 * 服务器错误 500，见 PanelExceptionHandler），不受宿主异常处理（例如「一律 HTTP 200 加业务码」）影响；
 * 上报仍交给宿主。
 *
 * 做法：面板路由组的第一个中间件。面板接口请求期间把容器里的异常处理换成 PanelExceptionHandler
 * （包住宿主的：渲染自己做，上报交给宿主），请求结束换回。路由管道在每一层捕获异常时都从容器取异常处理，
 * 所以排在它后面的中间件（宿主的 web 组、登录中间件、授权）与控制器抛的异常都经过它。
 *
 * 外壳页面（fail2ban.index）不接管：浏览器打开页面时未登录该怎么跳转，由宿主决定。
 * 宿主的登录中间件如果不抛异常、自己返回响应，那个响应原样返回：面板接口要求它对未登录的请求返回 401。
 */
class RenderPanelExceptions
{
    public function __construct(
        protected Container $container,
    ) {
    }

    public function handle(Request $request, Closure $next): Response
    {
        if ($request->route()?->named('fail2ban.index')) {
            return $next($request);
        }

        $host = $this->container->make(ExceptionHandler::class);

        $this->container->instance(ExceptionHandler::class, new PanelExceptionHandler($host, $this->container));

        try {
            return $next($request);
        } finally {
            $this->container->instance(ExceptionHandler::class, $host);
        }
    }
}
