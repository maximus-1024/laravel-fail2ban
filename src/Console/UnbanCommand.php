<?php

namespace Maximus\Fail2Ban\Console;

use Illuminate\Console\Command;
use Illuminate\Validation\ValidationException;
use Maximus\Fail2Ban\Contracts\AuditRepository;
use Maximus\Fail2Ban\Fail2Ban;
use Maximus\Fail2Ban\Operations;
use Symfony\Component\Console\Attribute\AsCommand;

#[AsCommand(name: 'fail2ban:unban')]
class UnbanCommand extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'fail2ban:unban {ip : IP 地址或访客键（IPv6 按 64 位网段）}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = '解除一个访客的封禁（管理员自己被封、打不开面板时用）';

    public function handle(Operations $operations): int
    {
        try {
            $ban = $operations->unban((string) $this->argument('ip'), Fail2Ban::actor(null), AuditRepository::VIA_CONSOLE);
        } catch (ValidationException $e) {
            $this->components->error(collect($e->errors())->flatten()->implode(' '));

            return self::FAILURE;
        }

        if ($ban === null) {
            $this->components->warn("{$this->argument('ip')} 当前没有封禁；已清除它的命中记录与累犯记录。");

            return self::FAILURE;
        }

        $this->components->info("已解封 {$ban['visitor']}（事件 {$ban['incident']}）。");

        return self::SUCCESS;
    }
}
