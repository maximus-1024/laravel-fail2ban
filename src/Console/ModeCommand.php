<?php

namespace Maximus\Fail2Ban\Console;

use Illuminate\Console\Command;
use Illuminate\Validation\ValidationException;
use Maximus\Fail2Ban\Contracts\AuditRepository;
use Maximus\Fail2Ban\Fail2Ban;
use Maximus\Fail2Ban\Operations;
use Symfony\Component\Console\Attribute\AsCommand;

#[AsCommand(name: 'fail2ban:mode')]
class ModeCommand extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'fail2ban:mode {mode : off（已关闭）| observe（观察）| block（拦截）}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = '切换运行模式';

    public function handle(Operations $operations): int
    {
        $mode = (string) $this->argument('mode');

        try {
            $operations->switchMode($mode, Fail2Ban::actor(null), AuditRepository::VIA_CONSOLE);
        } catch (ValidationException $e) {
            $this->components->error('运行模式只能是 off、observe、block 之一。');

            return self::FAILURE;
        }

        $this->components->info('运行模式已切换为「'.(Operations::MODE_LABELS[$mode] ?? $mode).'」。');

        if (! config('fail2ban.enabled')) {
            $this->components->warn('总开关 FAIL2BAN_ENABLED 是关闭的，运行模式要等总开关打开后才生效。');
        }

        return self::SUCCESS;
    }
}
