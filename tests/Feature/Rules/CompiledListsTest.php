<?php

namespace Maximus\Fail2Ban\Tests\Feature\Rules;

use Maximus\Fail2Ban\Inspector;
use Maximus\Fail2Ban\Rules\KnownExploit;
use Maximus\Fail2Ban\Rules\ScannerAgent;
use Maximus\Fail2Ban\Rules\SensitivePath;
use Maximus\Fail2Ban\Rules\Support\CompiledLists;
use PHPUnit\Framework\Attributes\Test;
use ReflectionProperty;

/**
 * 三份内置清单的编译产物 resources/rules/compiled.php（CompiledLists）。
 *
 * 文本清单是唯一的事实来源；产物随仓库提交，运行时 require 它（opcache 放进共享内存）。
 */
class CompiledListsTest extends RuleTestCase
{
    protected function tearDown(): void
    {
        $this->setCompiled(null);

        parent::tearDown();
    }

    /**
     * 直接换掉本进程已 require 的产物（测试用）。
     */
    private function setCompiled(?array $compiled): void
    {
        (new ReflectionProperty(CompiledLists::class, 'compiled'))->setValue(null, $compiled);
    }

    #[Test]
    public function the_committed_artifact_matches_the_text_lists(): void
    {
        $this->assertSame(
            CompiledLists::source(),
            file_get_contents(CompiledLists::FILE),
            'resources/rules/compiled.php 与 resources/rules/*.txt 不一致：改了文本清单要运行 composer compile-rules 重新生成，并一起提交。',
        );
    }

    #[Test]
    public function the_artifact_is_a_plain_literal_so_opcache_keeps_it_in_shared_memory(): void
    {
        // 只有字面量（没有函数调用、常量引用、拼接），opcache 才能把整个数组编成不可变数组
        $tokens = token_get_all(file_get_contents(CompiledLists::FILE));
        $code = array_filter($tokens, fn ($token) => ! is_array($token) || ! in_array($token[0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT, T_OPEN_TAG], true));
        $kinds = array_unique(array_map(fn ($token) => is_array($token) ? token_name($token[0]) : $token, $code));
        sort($kinds);

        $this->assertSame([',', ';', 'T_CONSTANT_ENCAPSED_STRING', 'T_DOUBLE_ARROW', 'T_RETURN', '[', ']'], $kinds);

        $compiled = require CompiledLists::FILE;

        foreach (Inspector::LIST_RULES as $id) {
            $class = Inspector::BUILTIN[$id];
            $this->assertSame($class::compile($class::builtinEntries()), $compiled[$class], $id);
        }

        $this->assertSame([KnownExploit::class, SensitivePath::class, ScannerAgent::class], array_keys($compiled));
    }

    #[Test]
    public function default_rules_take_the_artifact_and_customized_rules_compile_at_runtime(): void
    {
        // 换成一份假的产物：不配追加、排除的规则用的就是它，证明运行时不读文本清单
        $this->setCompiled([
            SensitivePath::class => ['regex' => '~^/only\-in\-artifact$~D'],
            KnownExploit::class => ['paths' => '~^/exploit\-in\-artifact$~D', 'queries' => '~(?!)~'],
            ScannerAgent::class => ['regex' => '~artifactbot~'],
        ]);

        $notFound = $this->response(404);

        $this->assertTrue((new SensitivePath)->matches($this->makeRequest('GET', '/only-in-artifact'), $notFound));
        $this->assertFalse((new SensitivePath)->matches($this->makeRequest('GET', '/.env'), $notFound));
        $this->assertTrue((new KnownExploit)->matches($this->makeRequest('GET', '/exploit-in-artifact'), $notFound));
        $this->assertTrue((new ScannerAgent)->matches($this->makeRequest('GET', '/', ['User-Agent' => 'ArtifactBot/1']), $notFound));
        $this->assertFalse((new ScannerAgent)->matches($this->makeRequest('GET', '/', ['User-Agent' => 'sqlmap/1.7']), $notFound));

        // 宿主追加或排除了条目：读文本清单现编，假产物不起作用
        $this->assertTrue((new SensitivePath(extra: ['/mine']))->matches($this->makeRequest('GET', '/.env'), $notFound));
        $this->assertFalse((new SensitivePath(extra: ['/mine']))->matches($this->makeRequest('GET', '/only-in-artifact'), $notFound));
        $this->assertTrue((new ScannerAgent(except: ['nikto']))->matches($this->makeRequest('GET', '/', ['User-Agent' => 'sqlmap/1.7']), $notFound));
        $this->assertTrue((new KnownExploit(except: ['*/voyager-assets*']))->matches($this->makeRequest('GET', '/_ignition/execute-solution'), $notFound));

        // 只写了空串、注释的追加与排除等于没配
        $this->assertTrue((new SensitivePath(extra: ['', '  ', '# 注释']))->matches($this->makeRequest('GET', '/only-in-artifact'), $notFound));
    }

    #[Test]
    public function a_host_subclass_of_a_builtin_rule_compiles_its_own_lists(): void
    {
        $rule = new class extends SensitivePath
        {
            public static function compile(array $entries): array
            {
                return parent::compile([...$entries, '/subclass-only']);
            }
        };

        $this->assertNull(CompiledLists::for($rule::class));
        $this->assertTrue($rule->matches($this->makeRequest('GET', '/subclass-only'), $this->response(404)));
        $this->assertTrue($rule->matches($this->makeRequest('GET', '/.env'), $this->response(404)));
    }
}
