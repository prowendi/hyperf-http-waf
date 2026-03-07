<?php

declare(strict_types=1);

namespace Prowendi\HyperfHttpWaf\Tests;

use Prowendi\HyperfHttpWaf\Tests\Stubs\OkHandler;
use Prowendi\HyperfHttpWaf\Tests\Stubs\SpyReporter;
use Nyholm\Psr7\Stream;
use Nyholm\Psr7\UploadedFile;

final class WafMiddlewareTest extends TestCase
{
    public function testNormalRequestPassesThrough(): void
    {
        $reporter = new SpyReporter();
        $middleware = $this->createMiddleware([
            'mode' => 'block',
        ], $reporter);

        $request = $this->createRequest('GET', '/api/users', [
            'user-agent' => 'Mozilla/5.0',
        ])->withQueryParams([
            'name' => 'alice',
        ]);

        $response = $middleware->process($request, new OkHandler());

        self::assertSame(200, $response->getStatusCode());
        self::assertSame('{"ok":true}', (string) $response->getBody());
        self::assertCount(0, $reporter->entries);
    }

    public function testSqlInjectionFeatureIsBlocked(): void
    {
        $reporter = new SpyReporter();
        $middleware = $this->createMiddleware([
            'mode' => 'block',
        ], $reporter);

        $request = $this->createRequest('GET', '/search', [
            'user-agent' => 'Mozilla/5.0',
        ])->withQueryParams([
            'q' => '1 union select password from users',
        ]);

        $response = $middleware->process($request, new OkHandler());

        self::assertSame(403, $response->getStatusCode());
        self::assertCount(1, $reporter->entries);
        self::assertSame('block', $reporter->entries[0]['result']->action->value);
        self::assertContains('sqli-union-select', array_map(
            static fn ($hit) => $hit->ruleId,
            $reporter->entries[0]['result']->hitRules
        ));
    }

    public function testXssFeatureIsBlocked(): void
    {
        $reporter = new SpyReporter();
        $middleware = $this->createMiddleware([
            'mode' => 'block',
            'decision' => [
                'score_threshold' => 50,
            ],
        ], $reporter);

        $request = $this->createRequest('GET', '/comments', [
            'user-agent' => 'Mozilla/5.0',
        ])->withQueryParams([
            'content' => '<script>alert(1)</script>',
        ]);

        $response = $middleware->process($request, new OkHandler());

        self::assertSame(403, $response->getStatusCode());
        self::assertSame('block', $reporter->entries[0]['result']->action->value);
    }

    public function testSensitivePathIsBlocked(): void
    {
        $reporter = new SpyReporter();
        $middleware = $this->createMiddleware([
            'mode' => 'block',
        ], $reporter);

        $request = $this->createRequest('GET', '/.env', [
            'user-agent' => 'Mozilla/5.0',
        ]);

        $response = $middleware->process($request, new OkHandler());

        self::assertSame(403, $response->getStatusCode());
        self::assertSame('block', $reporter->entries[0]['result']->action->value);
    }

    public function testWhitelistAllowsRequest(): void
    {
        $reporter = new SpyReporter();
        $middleware = $this->createMiddleware([
            'mode' => 'block',
            'decision' => [
                'score_threshold' => 1,
            ],
            'whitelist' => [
                'paths' => ['/safe*'],
            ],
        ], $reporter);

        $request = $this->createRequest('GET', '/safe/tool', [
            'user-agent' => 'Mozilla/5.0',
        ])->withQueryParams([
            'content' => '<script>alert(1)</script>',
        ]);

        $response = $middleware->process($request, new OkHandler());

        self::assertSame(200, $response->getStatusCode());
        self::assertCount(0, $reporter->entries);
    }

    public function testObserveModeOnlyReports(): void
    {
        $reporter = new SpyReporter();
        $middleware = $this->createMiddleware([
            'mode' => 'observe',
        ], $reporter);

        $request = $this->createRequest('GET', '/search', [
            'user-agent' => 'Mozilla/5.0',
        ])->withQueryParams([
            'q' => '1 union select username from users',
        ]);

        $response = $middleware->process($request, new OkHandler());

        self::assertSame(200, $response->getStatusCode());
        self::assertCount(1, $reporter->entries);
        self::assertSame('observe', $reporter->entries[0]['result']->action->value);
    }

    public function testBlockModeInterceptsIllegalMethod(): void
    {
        $reporter = new SpyReporter();
        $middleware = $this->createMiddleware([
            'mode' => 'block',
        ], $reporter);

        $request = $this->createRequest('TRACE', '/api/trace', [
            'user-agent' => 'Mozilla/5.0',
        ]);

        $response = $middleware->process($request, new OkHandler());

        self::assertSame(403, $response->getStatusCode());
        self::assertSame('block', $reporter->entries[0]['result']->action->value);
    }

    public function testBodySizeLimitCanTriggerBlock(): void
    {
        $reporter = new SpyReporter();
        $middleware = $this->createMiddleware([
            'mode' => 'block',
            'body_size_limit' => 16,
            'decision' => [
                'score_threshold' => 30,
            ],
        ], $reporter);

        $request = $this->createRequest(
            'POST',
            '/submit',
            [
                'content-type' => 'text/plain',
                'user-agent' => 'Mozilla/5.0',
            ],
            str_repeat('a', 32)
        );

        $response = $middleware->process($request, new OkHandler());

        self::assertSame(403, $response->getStatusCode());
        self::assertSame('block', $reporter->entries[0]['result']->action->value);
    }

    public function testFileUploadMetadataDetection(): void
    {
        $reporter = new SpyReporter();
        $middleware = $this->createMiddleware([
            'mode' => 'block',
        ], $reporter);

        $request = $this->createRequest('POST', '/upload', [
            'user-agent' => 'Mozilla/5.0',
        ])->withUploadedFiles([
            'avatar' => new UploadedFile(
                Stream::create('<?php echo 1;'),
                14,
                UPLOAD_ERR_OK,
                'shell.php',
                'application/x-php'
            ),
        ]);

        $response = $middleware->process($request, new OkHandler());

        self::assertSame(403, $response->getStatusCode());
        self::assertSame('block', $reporter->entries[0]['result']->action->value);
    }

    public function testHeaderMaliciousPayloadDetection(): void
    {
        $reporter = new SpyReporter();
        $middleware = $this->createMiddleware([
            'mode' => 'block',
            'decision' => [
                'score_threshold' => 50,
            ],
        ], $reporter);

        $request = $this->createRequest('GET', '/api/header', [
            'user-agent' => 'Mozilla/5.0',
            'x-test' => '<script>alert(1)</script>',
        ]);

        $response = $middleware->process($request, new OkHandler());

        self::assertSame(403, $response->getStatusCode());
        self::assertSame('block', $reporter->entries[0]['result']->action->value);
    }

    public function testLocalhostOriginAndHostAreNotBlockedByDefaultHeaderScanning(): void
    {
        $reporter = new SpyReporter();
        $middleware = $this->createMiddleware([
            'mode' => 'block',
            'decision' => [
                'score_threshold' => 45,
            ],
        ], $reporter);

        $request = $this->createRequest('POST', 'http://127.0.0.1:9501/auth/login', [
            'host' => '127.0.0.1:9501',
            'origin' => 'http://localhost:5173',
            'referer' => 'http://localhost:5173/login',
            'content-type' => 'application/json',
            'user-agent' => 'Mozilla/5.0',
        ], '{"username":"alice","password":"secret"}');

        $response = $middleware->process($request, new OkHandler());

        self::assertSame(200, $response->getStatusCode());
        self::assertCount(0, $reporter->entries);
    }
}
