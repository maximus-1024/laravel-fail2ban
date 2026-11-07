<?php

namespace Maximus\Fail2Ban\Tests\Feature\Rules;

use Maximus\Fail2Ban\Rules\ScannerAgent;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

class ScannerAgentTest extends RuleTestCase
{
    public static function scannerAgents(): array
    {
        return [
            'sqlmap' => ['sqlmap/1.7.2#stable (https://sqlmap.org)'],
            'sqlmap 大写' => ['SQLMAP/1.8'],
            'nikto' => ['Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:000001)'],
            'nuclei' => ['Nuclei - Open-source project (github.com/projectdiscovery/nuclei)'],
            'zgrab' => ['Mozilla/5.0 zgrab/0.x'],
            'masscan' => ['masscan/1.3 (https://github.com/robertdavidgraham/masscan)'],
            'nmap' => ['Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)'],
            'wpscan' => ['WPScan v3.8.25 (https://wpscan.com/wordpress-security-scanner)'],
            'dirbuster' => ['DirBuster-1.0-RC1 (http://www.owasp.org/index.php/Category:OWASP_DirBuster_Project)'],
            'gobuster' => ['gobuster/3.6'],
            'ffuf 默认' => ['Fuzz Faster U Fool v2.1.0-dev'],
            'feroxbuster' => ['feroxbuster/2.10.4'],
            'acunetix' => ['Mozilla/5.0 (Windows NT 10.0) Acunetix-Product/14'],
            'nessus' => ['Nessus SOAP'],
            'openvas' => ['OpenVAS-VT 22.4'],
            'whatweb' => ['WhatWeb/0.5.5'],
            'wfuzz' => ['Wfuzz/3.1.0'],
            'commix' => ['commix/v3.9-stable'],
            'hydra' => ['Mozilla/4.0 (Hydra)'],
            '夹在浏览器标识里' => ['Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36 nuclei'],
        ];
    }

    #[Test]
    #[DataProvider('scannerAgents')]
    public function known_scanners_match(string $agent): void
    {
        $this->assertTrue((new ScannerAgent)->matches(
            $this->makeRequest('GET', '/v1/prepay/abc', ['User-Agent' => $agent]),
            $this->response(200),
        ), $agent);
    }

    public static function ordinaryAgents(): array
    {
        return [
            'curl' => ['curl/8.5.0'],
            'Guzzle' => ['GuzzleHttp/7'],
            'Guzzle 带 curl 与 PHP' => ['GuzzleHttp/7 curl/8.5.0 PHP/8.3.1'],
            'okhttp' => ['okhttp/4.12.0'],
            'python-requests' => ['python-requests/2.31.0'],
            'python-httpx' => ['python-httpx/0.27.0'],
            'aiohttp' => ['Python/3.12 aiohttp/3.9.1'],
            'Go 1.1' => ['Go-http-client/1.1'],
            'Go 2.0' => ['Go-http-client/2.0'],
            'Java' => ['Java/17.0.2'],
            'Apache HttpClient' => ['Apache-HttpClient/4.5.14 (Java/17.0.9)'],
            'axios' => ['axios/1.6.2'],
            'node-fetch' => ['node-fetch/1.0 (+https://github.com/bitinn/node-fetch)'],
            'undici' => ['undici'],
            'node' => ['node'],
            'Postman' => ['PostmanRuntime/7.36.0'],
            'Wget' => ['Wget/1.21.4'],
            'PHP' => ['PHP/8.3'],
            'libcurl' => ['libcurl/7.88.1'],
            'Chrome' => ['Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36'],
            'iPhone 微信' => ['Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 MicroMessenger/8.0.47(0x18002f2c) NetType/WIFI Language/zh_CN'],
            'Android' => ['Mozilla/5.0 (Linux; Android 14; 23127PN0CC) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0 Mobile Safari/537.36'],
            '只是包含 nmap 字母' => ['unmapped-client/1.0'],
            '只是包含 nikto 字母' => ['Mozilla/5.0 niktoolkit/2'],
            '前面紧挨字母' => ['acmenmap-agent/1.0'],
            '前面紧挨数字' => ['client2sqlmap'],
            '去掉的条目 Mozilla/6.0' => ['Mozilla/6.0 (compatible)'],
            '去掉的条目 hexometer' => ['Hexometer'],
        ];
    }

    #[Test]
    #[DataProvider('ordinaryAgents')]
    public function generic_clients_and_browsers_do_not_match(string $agent): void
    {
        $this->assertFalse((new ScannerAgent)->matches(
            $this->makeRequest('POST', '/v1/transactions/pay', ['User-Agent' => $agent]),
            $this->response(200),
        ), $agent);
    }

    #[Test]
    public function empty_or_missing_agent_does_not_match(): void
    {
        $rule = new ScannerAgent;

        $this->assertFalse($rule->matches($this->makeRequest('GET', '/', ['User-Agent' => '']), $this->response(404)));
        $this->assertFalse($rule->matches($this->makeRequest('GET', '/', ['User-Agent' => null]), $this->response(404)));
        $this->assertFalse($rule->matches($this->makeRequest('GET', '/', ['User-Agent' => '   ']), $this->response(404)));
    }

    #[Test]
    public function status_code_does_not_matter(): void
    {
        $rule = new ScannerAgent;
        $request = $this->makeRequest('GET', '/v1/prepay/abc', ['User-Agent' => 'sqlmap/1.7']);

        foreach ([200, 302, 404, 500] as $status) {
            $this->assertTrue($rule->matches($request, $this->response($status)), (string) $status);
        }
    }

    #[Test]
    public function every_request_counts(): void
    {
        $rule = new ScannerAgent;

        $this->assertNull($rule->key($this->makeRequest('GET', '/a', ['User-Agent' => 'sqlmap/1.7'])));
        $this->assertNull($rule->key($this->makeRequest('GET', '/a?x=1', ['User-Agent' => 'sqlmap/1.7'])));
    }

    #[Test]
    public function list_has_crs_entries_and_no_generic_libraries(): void
    {
        $entries = array_map('strtolower', ScannerAgent::builtinEntries());

        foreach (['sqlmap', 'nikto', 'nuclei', 'zgrab', 'masscan', 'nmap', 'wpscan', 'dirbuster', 'gobuster', 'fuzz faster', 'feroxbuster', 'acunetix', 'nessus', 'openvas', 'whatweb'] as $tool) {
            $this->assertContains($tool, $entries);
        }

        foreach (['curl', 'guzzle', 'okhttp', 'python-requests', 'httpx', 'go-http-client', 'java/', 'axios', 'node-fetch', 'undici', 'wget', 'httpclient', 'postman', 'libwww', 'mozilla/6.0'] as $generic) {
            foreach ($entries as $entry) {
                $this->assertStringNotContainsString($generic, $entry, "清单里不能有通用库：$entry");
            }
        }
    }
}
