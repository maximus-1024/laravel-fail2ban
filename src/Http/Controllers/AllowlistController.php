<?php

namespace Maximus\Fail2Ban\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Validation\ValidationException;
use Maximus\Fail2Ban\Contracts\AllowlistRepository;
use Maximus\Fail2Ban\Contracts\AuditRepository;
use Maximus\Fail2Ban\Fail2Ban;
use Maximus\Fail2Ban\Http\Presenter;
use Maximus\Fail2Ban\Operations;

class AllowlistController extends Controller
{
    public function index(AllowlistRepository $allowlist, Presenter $presenter)
    {
        return response()->json([
            'builtin' => array_map(fn (array $entry) => [
                'entry' => $entry['entry'],
                'label' => $entry['label'],
            ], $allowlist->builtin()),
            'data' => array_map(fn (array $entry) => $presenter->allowEntry($entry), $allowlist->entries()),
        ]);
    }

    /**
     * 添加条目，同时解封落在其中的当前封禁。
     */
    public function store(Request $request, Operations $operations, Presenter $presenter)
    {
        $record = $operations->allow(
            is_string($entry = $request->input('entry')) ? $entry : '',
            is_string($note = $request->input('note')) ? $note : null,
            Fail2Ban::actor($request),
            AuditRepository::VIA_PANEL,
        );

        return response()->json($presenter->allowEntry($record), 201);
    }

    /**
     * 删除条目。条目放在查询参数 entry 里（网段含斜杠，不放进路径）。
     */
    public function destroy(Request $request, Operations $operations)
    {
        $entry = $this->filter($request, 'entry') ?? throw ValidationException::withMessages(['entry' => ['请指定要删除的条目。']]);

        return $operations->disallow($entry, Fail2Ban::actor($request), AuditRepository::VIA_PANEL)
            ? response()->noContent()
            : response()->json(['message' => '白名单里没有这个条目。'], 404);
    }
}
