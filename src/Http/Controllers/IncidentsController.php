<?php

namespace Maximus\Fail2Ban\Http\Controllers;

use Illuminate\Http\Request;
use Maximus\Fail2Ban\Contracts\BanRepository;
use Maximus\Fail2Ban\Contracts\IncidentRepository;
use Maximus\Fail2Ban\Http\Presenter;

class IncidentsController extends Controller
{
    public function index(Request $request, IncidentRepository $incidents, Presenter $presenter)
    {
        [$page, $perPage] = $this->pagination($request);

        $result = $incidents->paginate([
            'disposition' => $this->filter($request, 'disposition'),
            'rule' => $this->filter($request, 'rule'),
            'q' => $this->filter($request, 'q'),
        ], $page, $perPage);

        return response()->json([
            'data' => array_map(fn (array $incident) => $presenter->incident($incident), $result['data']),
        ] + $result);
    }

    public function show(string $id, IncidentRepository $incidents, BanRepository $bans, Presenter $presenter)
    {
        $incident = $incidents->find($id);

        if ($incident === null) {
            return response()->json(['message' => '事件不存在，可能已超出保留条数。'], 404);
        }

        return response()->json($presenter->incidentDetail($incident, $bans->find($incident['visitor'])));
    }
}
