<?php

namespace Maximus\Fail2Ban\Http\Responses;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Support\Responsable;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response as HttpResponse;
use Illuminate\Routing\Router;
use Maximus\Fail2Ban\Fail2Ban;
use Symfony\Component\HttpFoundation\Response;

/**
 * 给被封访客的拒绝响应。
 *
 * 载荷（$payload）：
 *
 *     [
 *         'status' => int,           // 设置里的 response.status
 *         'message' => string,       // 设置里的 response.message
 *         'ip' => ?string,           // 访客 IP（$request->ip()）；show_ip 关闭时为 null
 *         'incident' => ?string,     // 事件编号；show_incident 关闭时为 null
 *         'recorded_at' => ?string,  // 封禁时间，应用时区，Y-m-d H:i:s；show_time 关闭时为 null
 *         'format' => 'html'|'json', // 按包的默认规则这次会给页面还是 JSON（见 format()），
 *                                    // 宿主替换外形时据此给浏览器页面（可直接渲染视图 fail2ban::blocked）
 *     ]
 *
 * 不含、也不能推出封禁何时结束。
 *
 * 外形：
 *  - 宿主登记了 Fail2Ban::respondUsing() 时，调用
 *    `fn (\Illuminate\Http\Request $request, array $payload): mixed`，
 *    返回值可以是任何路由能返回的东西（Response、Responsable、数组、字符串……），
 *    由 Router::toResponse() 转成响应；
 *  - 否则 Accept 明确包含 text/html 时给页面 fail2ban::blocked，其余（没有 Accept、只有通配类型、
 *    application/json……）一律给 JSON：{"code": 状态码, "message": "...", "data": {ip, incident, recorded_at}}，
 *    关掉的项不出现。
 *
 * 无论哪种外形，状态码都强制为 payload.status，并加上 Cache-Control: no-store 与 X-Robots-Tag: noindex。
 */
class BlockedResponse implements Responsable
{
    /**
     * Create a new response instance.
     *
     * @param  array{status: int, message: string, ip: ?string, incident: ?string, recorded_at: ?string, format: 'html'|'json'}  $payload
     */
    public function __construct(
        public readonly array $payload,
    ) {
    }

    /**
     * 按封禁与「拒绝响应」设置组装。
     *
     * @param  array{incident: string, banned_at: int}  $ban  BanRepository::lookup() 返回的 ban
     * @param  array{status: int, message: string, show_ip: bool, show_incident: bool, show_time: bool}  $settings  设置里的 response
     */
    public static function make(Request $request, array $ban, array $settings): static
    {
        return new static([
            'status' => (int) $settings['status'],
            'message' => (string) $settings['message'],
            'ip' => ! empty($settings['show_ip']) ? $request->ip() : null,
            'incident' => ! empty($settings['show_incident']) ? $ban['incident'] : null,
            'recorded_at' => ! empty($settings['show_time'])
                ? CarbonImmutable::createFromTimestamp($ban['banned_at'], config('app.timezone', 'UTC'))->format('Y-m-d H:i:s')
                : null,
            'format' => static::format($request),
        ]);
    }

    /**
     * Create an HTTP response that represents the object.
     *
     * @param  \Illuminate\Http\Request  $request
     */
    public function toResponse($request): Response
    {
        $responder = Fail2Ban::responder();

        $response = $responder
            ? Router::toResponse($request, $responder($request, $this->payload))
            : $this->defaultResponse($request);

        $response->setStatusCode($this->payload['status']);
        $response->headers->set('Cache-Control', 'no-store');
        $response->headers->set('X-Robots-Tag', 'noindex');

        return $response;
    }

    /**
     * 包自带的外形：浏览器给页面，其余给 JSON。
     */
    protected function defaultResponse(Request $request): Response
    {
        if ($this->wantsPage($request)) {
            return new HttpResponse(view('fail2ban::blocked', [
                'status' => $this->payload['status'],
                'message' => $this->payload['message'],
                'ip' => $this->payload['ip'],
                'incident' => $this->payload['incident'],
                'recordedAt' => $this->payload['recorded_at'],
            ])->render(), $this->payload['status'], ['Content-Type' => 'text/html; charset=UTF-8']);
        }

        $data = array_filter([
            'ip' => $this->payload['ip'],
            'incident' => $this->payload['incident'],
            'recorded_at' => $this->payload['recorded_at'],
        ], fn ($value) => $value !== null);

        return new JsonResponse([
            'code' => $this->payload['status'],
            'message' => $this->payload['message'],
            'data' => (object) $data,
        ], $this->payload['status'], [], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    }

    /**
     * Accept 明确列出 text/html 才算浏览器。调接口的服务器通常不带 Accept 或只带通配类型，它们拿到 JSON。
     */
    protected function wantsPage(Request $request): bool
    {
        return static::format($request) === 'html';
    }

    /**
     * 按包的默认规则，这次请求该给页面（html）还是 JSON（json）：Accept 明确列出 text/html 才给页面。
     *
     * @return 'html'|'json'
     */
    public static function format(Request $request): string
    {
        return in_array('text/html', $request->getAcceptableContentTypes(), true) ? 'html' : 'json';
    }
}
