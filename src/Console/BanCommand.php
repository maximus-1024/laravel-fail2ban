<?php

namespace Maximus\Fail2Ban\Console;

use Illuminate\Console\Command;
use Illuminate\Validation\ValidationException;
use Maximus\Fail2Ban\Contracts\AuditRepository;
use Maximus\Fail2Ban\Fail2Ban;
use Maximus\Fail2Ban\Operations;
use Symfony\Component\Console\Attribute\AsCommand;

#[AsCommand(name: 'fail2ban:ban')]
class BanCommand extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'fail2ban:ban
                            {ip : 要封禁的 IP 地址}
                            {--minutes=60 : 封禁时长，单位分钟}
                            {--note= : 备注}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = '手动封禁一个 IP（以这次为准，覆盖已有的封禁）';

    public function handle(Operations $operations): int
    {
        try {
            $ban = $operations->ban(
                (string) $this->argument('ip'),
                $this->option('minutes'),
                $this->option('note'),
                Fail2Ban::actor(null),
                AuditRepository::VIA_CONSOLE,
            );
        } catch (ValidationException $e) {
            $this->components->error(collect($e->errors())->flatten()->implode(' '));

            return self::FAILURE;
        }

        $this->components->info("已封禁 {$ban['visitor']} {$ban['ban_minutes']} 分钟（事件 {$ban['incident']}）。");

        return self::SUCCESS;
    }
}
