<?php

namespace Maximus\Fail2Ban\Http\Controllers;

use Illuminate\Http\Request;
use Maximus\Fail2Ban\Contracts\AuditRepository;
use Maximus\Fail2Ban\Http\Presenter;

class AuditController extends Controller
{
    public function index(Request $request, AuditRepository $audit, Presenter $presenter)
    {
        [$page, $perPage] = $this->pagination($request);

        $result = $audit->paginate($this->filter($request, 'action'), $page, $perPage);

        return response()->json([
            'data' => array_map(fn (array $entry) => $presenter->audit($entry), $result['data']),
        ] + $result);
    }
}
