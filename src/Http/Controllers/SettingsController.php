<?php

namespace Maximus\Fail2Ban\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Validation\ValidationException;
use Maximus\Fail2Ban\Contracts\AuditRepository;
use Maximus\Fail2Ban\Contracts\SettingsRepository;
use Maximus\Fail2Ban\Fail2Ban;
use Maximus\Fail2Ban\Http\SettingsTransformer;
use Maximus\Fail2Ban\Operations;

class SettingsController extends Controller
{
    public function show(SettingsRepository $settings, SettingsTransformer $transformer)
    {
        return response()->json($transformer->toApi($settings->all()));
    }

    /**
     * 保存设置。校验在存储层；这里只转换形状，并把错误键转回接口字段名。
     */
    public function update(Request $request, Operations $operations, SettingsTransformer $transformer)
    {
        [$changes, $paths] = $transformer->fromApi($request->post());

        try {
            $settings = $operations->saveSettings($changes, Fail2Ban::actor($request), AuditRepository::VIA_PANEL);
        } catch (ValidationException $e) {
            throw ValidationException::withMessages($transformer->errorsToApi($e->errors(), $paths));
        }

        return response()->json($transformer->toApi($settings));
    }
}
