<?php

use Illuminate\Support\Facades\Route;
use Maximus\Fail2Ban\Http\Controllers\AllowlistController;
use Maximus\Fail2Ban\Http\Controllers\AuditController;
use Maximus\Fail2Ban\Http\Controllers\BansController;
use Maximus\Fail2Ban\Http\Controllers\HomeController;
use Maximus\Fail2Ban\Http\Controllers\IncidentsController;
use Maximus\Fail2Ban\Http\Controllers\OverviewController;
use Maximus\Fail2Ban\Http\Controllers\SettingsController;

/*
| 面板路由。由 Fail2BanServiceProvider::registerRoutes() 套上前缀 config('fail2ban.panel.path')、
| 中间件 config('fail2ban.panel.middleware') 与授权 can:viewFail2Ban 后加载。
*/

Route::prefix('api')->name('fail2ban.')->group(function () {
    // 安全总览
    Route::get('/overview', [OverviewController::class, 'index'])->name('overview');

    // 攻击事件
    Route::get('/incidents', [IncidentsController::class, 'index'])->name('incidents.index');
    Route::get('/incidents/{id}', [IncidentsController::class, 'show'])->name('incidents.show');

    // 封禁列表。删除用查询参数 visitor：访客键里有冒号与斜杠，放进路径过 nginx 有被拒或被改写的风险。
    Route::get('/bans', [BansController::class, 'index'])->name('bans.index');
    Route::post('/bans', [BansController::class, 'store'])->name('bans.store');
    Route::delete('/bans', [BansController::class, 'destroy'])->name('bans.destroy');

    // 白名单。删除用查询参数 entry（网段里有斜杠，理由同上）。
    Route::get('/allowlist', [AllowlistController::class, 'index'])->name('allowlist.index');
    Route::post('/allowlist', [AllowlistController::class, 'store'])->name('allowlist.store');
    Route::delete('/allowlist', [AllowlistController::class, 'destroy'])->name('allowlist.destroy');

    // 防护配置
    Route::get('/settings', [SettingsController::class, 'show'])->name('settings.show');
    Route::put('/settings', [SettingsController::class, 'update'])->name('settings.update');

    // 操作日志
    Route::get('/audit', [AuditController::class, 'index'])->name('audit.index');
});

// 外壳页面：面板地址下除 api 以外的任何子路径（单页应用用 history 路由）。
Route::get('/{view?}', [HomeController::class, 'index'])
    ->where('view', '(?!api(?:/|$)).*')
    ->name('fail2ban.index');
