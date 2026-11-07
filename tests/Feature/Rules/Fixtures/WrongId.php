<?php

namespace Maximus\Fail2Ban\Tests\Feature\Rules\Fixtures;

/**
 * 测试用：id() 与登记的标识对不上。
 */
class WrongId extends LegacyApiPath
{
    public function id(): string
    {
        return 'something-else';
    }
}
