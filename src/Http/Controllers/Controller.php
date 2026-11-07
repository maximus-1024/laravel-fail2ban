<?php

namespace Maximus\Fail2Ban\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Routing\Controller as BaseController;

/**
 * 面板控制器的基类（照 Horizon 的 Http\Controllers\Controller）。
 */
abstract class Controller extends BaseController
{
    /**
     * 分页参数：page 至少 1；per_page 在 1 到 100 之间，默认 20。
     *
     * @return array{0: int, 1: int}
     */
    protected function pagination(Request $request): array
    {
        $page = max(1, $request->integer('page', 1));
        $perPage = min(100, max(1, $request->integer('per_page', 20)));

        return [$page, $perPage];
    }

    /**
     * 可选的字符串筛选参数；空串与非字符串按没传。
     */
    protected function filter(Request $request, string $key): ?string
    {
        $value = $request->query($key);

        return is_string($value) && trim($value) !== '' ? trim($value) : null;
    }
}
