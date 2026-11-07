<?php

namespace Maximus\Fail2Ban\Http\Controllers;

use Illuminate\Http\Request;
use Maximus\Fail2Ban\Fail2Ban;

/**
 * 面板外壳页面：承载单页应用。面板地址下除 /api 以外的任何子路径都返回它（history 路由）。
 */
class HomeController extends Controller
{
    public function index(Request $request)
    {
        $path = $request->getBaseUrl().'/'.trim((string) config('fail2ban.panel.path', 'fail2ban'), '/');

        return response()
            ->view('fail2ban::layout', [
                'fail2ban' => [
                    'path' => $path,
                    'api' => $path.'/api',
                    'user' => Fail2Ban::actor($request),
                ],
            ])
            ->header('Cache-Control', 'no-store, private');
    }
}
