<?php

namespace Maximus\Fail2Ban\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Validation\ValidationException;
use Maximus\Fail2Ban\Contracts\AuditRepository;
use Maximus\Fail2Ban\Contracts\BanRepository;
use Maximus\Fail2Ban\Fail2Ban;
use Maximus\Fail2Ban\Http\Presenter;
use Maximus\Fail2Ban\Operations;

class BansController extends Controller
{
    /**
     * 当前封禁，按解封时间升序。rule 是规则标识或 manual；q 见 BanRepository::all()。
     */
    public function index(Request $request, BanRepository $bans, Presenter $presenter)
    {
        $data = $bans->all([
            'rule' => $this->filter($request, 'rule'),
            'q' => $this->filter($request, 'q'),
        ]);

        return response()->json([
            'data' => array_map(fn (array $ban) => $presenter->ban($ban), $data),
            'total' => count($data),
        ]);
    }

    /**
     * 手动封禁。面板要求填写备注。
     */
    public function store(Request $request, Operations $operations, Presenter $presenter)
    {
        $ban = $operations->ban(
            (string) $request->input('ip', ''),
            $request->input('minutes'),
            is_string($note = $request->input('note')) ? $note : null,
            Fail2Ban::actor($request),
            AuditRepository::VIA_PANEL,
            $request,
            requireNote: true,
        );

        return response()->json($presenter->ban($ban), 201);
    }

    /**
     * 解封。访客键放在查询参数 visitor 里（含冒号与斜杠，不放进路径）。
     * 当时没有被封时回 404（命中记录与累犯记录照样清掉，并写操作日志）。
     */
    public function destroy(Request $request, Operations $operations)
    {
        $visitor = $this->filter($request, 'visitor') ?? throw ValidationException::withMessages(['visitor' => ['请指定要解封的访客。']]);

        $ban = $operations->unban($visitor, Fail2Ban::actor($request), AuditRepository::VIA_PANEL);

        return $ban === null
            ? response()->json(['message' => '这个访客当前没有封禁，可能已经到期或被解封。'], 404)
            : response()->noContent();
    }
}
