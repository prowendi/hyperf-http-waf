<?php

declare(strict_types=1);

namespace Prowendi\HyperfHttpWaf\Tests;

use Prowendi\HyperfHttpWaf\Tests\Stubs\OkHandler;
use Nyholm\Psr7\Stream;
use Nyholm\Psr7\UploadedFile;

/**
 * Guards against false positives: ordinary application traffic must pass
 * through the WAF untouched in enforce (block) mode.
 */
final class WafFalsePositiveTest extends TestCase
{
    /**
     * @return iterable<string, list<string>>
     */
    public static function benignQueryProvider(): iterable
    {
        yield 'plain search' => ['hello world'];
        yield 'apostrophe text' => ["I don't like it, it's fine"];
        yield 'hashtag after word' => ['loving it #friday'];
        yield 'logical operators' => ['a && b || c'];
        yield 'pipe separated' => ['red|green|blue'];
        yield 'comparison in prose' => ['where the count = 1 and total = 2'];
        yield 'markdown content' => ["## Heading\n- item one\n- item two"];
        yield 'url value' => ['https://example.com/docs/page?section=3'];
        yield 'json pointer' => ['/data/attributes/0/name'];
        yield 'data image uri' => ['data:image/png;base64,iVBORw0KGgo='];
        yield 'relative path' => ['./assets/logo.png'];
        yield 'callback param' => ['jQuery31108493258561_1480395242'];
        yield 'jwt token' => ['eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc'];
        yield 'version string' => ['1.2.3-beta.4+build.5'];
        yield 'unicode text' => ['español año 東京 🎉'];
        yield 'c plus plus query' => ['c++ tutorial for beginners'];
        yield 'html anchor snippet' => ['<a href="https://example.com">link</a>'];
    }

    /**
     * @dataProvider benignQueryProvider
     */
    public function testBenignQueryValuesAreNotBlocked(string $value): void
    {
        $middleware = $this->createMiddleware(['mode' => 'block']);

        $request = $this->createRequest('GET', '/search', ['user-agent' => 'Mozilla/5.0'])
            ->withQueryParams(['q' => $value]);

        self::assertSame(200, $middleware->process($request, new OkHandler())->getStatusCode(), $value);
    }

    public function testBrowserUserAgentPasses(): void
    {
        $middleware = $this->createMiddleware(['mode' => 'block']);

        $request = $this->createRequest('GET', '/', [
            'user-agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
        ]);

        self::assertSame(200, $middleware->process($request, new OkHandler())->getStatusCode());
    }

    public function testRefererFromOwnSitePasses(): void
    {
        $middleware = $this->createMiddleware(['mode' => 'block']);

        $request = $this->createRequest('GET', '/dashboard', [
            'user-agent' => 'Mozilla/5.0',
            'referer' => 'https://example.com/settings?tab=security&lang=en',
        ]);

        self::assertSame(200, $middleware->process($request, new OkHandler())->getStatusCode());
    }

    public function testJsonApiBodyPasses(): void
    {
        $middleware = $this->createMiddleware(['mode' => 'block']);

        $request = $this->createRequest('POST', '/api/profile', [
            'content-type' => 'application/json',
            'user-agent' => 'Mozilla/5.0',
        ], '{"bio":"I build things","links":["https://github.com"],"expr":"a || b"}');

        self::assertSame(200, $middleware->process($request, new OkHandler())->getStatusCode());
    }

    public function testUrlencodedFormBodyPasses(): void
    {
        $middleware = $this->createMiddleware(['mode' => 'block']);

        $request = $this->createRequest('POST', '/contact', [
            'content-type' => 'application/x-www-form-urlencoded',
            'user-agent' => 'Mozilla/5.0',
        ], 'name=Alice+Johnson&message=Hello+there+%23general&ref=%2Fhome');

        self::assertSame(200, $middleware->process($request, new OkHandler())->getStatusCode());
    }

    public function testCookieSessionValuePasses(): void
    {
        $middleware = $this->createMiddleware(['mode' => 'block']);

        $request = $this->createRequest('GET', '/', ['user-agent' => 'Mozilla/5.0'])
            ->withCookieParams([
                'session' => 'eyJhbGciOiJIUzI1NiJ9.eyJ1aWQiOjQyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
                'theme' => 'dark-mode',
                'lang' => 'en-US',
            ]);

        self::assertSame(200, $middleware->process($request, new OkHandler())->getStatusCode());
    }

    public function testApiStyleHeadersPass(): void
    {
        $middleware = $this->createMiddleware(['mode' => 'block']);

        $request = $this->createRequest('POST', '/api/pipeline', [
            'user-agent' => 'Mozilla/5.0',
            'x-request-id' => 'a1b2c3d4-e5f6-7890-abcd-ef1234567890',
            'x-trace-step' => 'transform|filter|load',
            'accept' => 'application/vnd.api+json',
        ], '{}');

        self::assertSame(200, $middleware->process($request, new OkHandler())->getStatusCode());
    }

    public function testLegitimateRouteAndPaginationPass(): void
    {
        $middleware = $this->createMiddleware(['mode' => 'block']);

        $request = $this->createRequest('GET', '/api/v1/users/42/posts?page=3&per_page=25&sort=-created_at', [
            'user-agent' => 'Mozilla/5.0',
        ]);

        self::assertSame(200, $middleware->process($request, new OkHandler())->getStatusCode());
    }

    public function testWhitelistedHealthEndpointStillPasses(): void
    {
        $middleware = $this->createMiddleware(['mode' => 'block']);

        $request = $this->createRequest('GET', '/health', ['user-agent' => 'Mozilla/5.0']);

        self::assertSame(200, $middleware->process($request, new OkHandler())->getStatusCode());
    }

    /**
     * @return iterable<string, list<string>>
     */
    public static function benignSqlIshProvider(): iterable
    {
        yield 'order by column name' => ['ORDER BY price DESC'];
        yield 'substring api param' => ['substring(title,1,10)'];
        yield 'left pagination param' => ['left(10)'];
        yield 'normal jwt token' => ['eyJhbGciOiJIUzI1NiJ9.eyJ1aWQiOjQyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'];
        yield 'template variable' => ['{{user.name}}'];
        yield 'aws discussion text' => ['remember to rotate the akia credentials quarterly'];
    }

    /**
     * @dataProvider benignSqlIshProvider
     */
    public function testBenignSqlIshValuesAreNotBlocked(string $value): void
    {
        $middleware = $this->createMiddleware([
            'mode' => 'block',
            'decision' => ['score_threshold' => 40],
        ]);

        $request = $this->createRequest('GET', '/search', ['user-agent' => 'Mozilla/5.0'])
            ->withQueryParams(['q' => $value]);

        self::assertSame(200, $middleware->process($request, new OkHandler())->getStatusCode(), $value);
    }

    public function testCleanSvgUploadPasses(): void
    {
        $middleware = $this->createMiddleware(['mode' => 'block']);

        $request = $this->createRequest('POST', '/logo', [
            'user-agent' => 'Mozilla/5.0',
        ])->withUploadedFiles([
            'logo' => new UploadedFile(
                Stream::create('<?xml version="1.0" encoding="UTF-8"?><svg xmlns="http://www.w3.org/2000/svg" width="10" height="10"><rect width="10" height="10" fill="red"/></svg>'),
                180,
                UPLOAD_ERR_OK,
                'logo.svg',
                'image/svg+xml'
            ),
        ]);

        self::assertSame(200, $middleware->process($request, new OkHandler())->getStatusCode());
    }

    public function testPlainTextFileUploadPasses(): void
    {
        $middleware = $this->createMiddleware(['mode' => 'block']);

        $request = $this->createRequest('POST', '/notes', [
            'user-agent' => 'Mozilla/5.0',
        ])->withUploadedFiles([
            'note' => new UploadedFile(
                Stream::create("meeting notes\n- review pricing\n- ship friday"),
                48,
                UPLOAD_ERR_OK,
                'notes.txt',
                'text/plain'
            ),
        ]);

        self::assertSame(200, $middleware->process($request, new OkHandler())->getStatusCode());
    }

    public function testJsonLdTypeFieldPasses(): void
    {
        $middleware = $this->createMiddleware(['mode' => 'block']);

        $request = $this->createRequest('POST', '/ld', [
            'content-type' => 'application/json',
            'user-agent' => 'Mozilla/5.0',
        ], '{"@type":"Person","name":"Alice","knows":"https://example.com/bob"}');

        self::assertSame(200, $middleware->process($request, new OkHandler())->getStatusCode());
    }

    public function testNormalFilterParamPasses(): void
    {
        $middleware = $this->createMiddleware(['mode' => 'block']);

        $request = $this->createRequest('GET', '/products', ['user-agent' => 'Mozilla/5.0'])
            ->withQueryParams(['filter' => 'category', 'op' => 'eq']);

        self::assertSame(200, $middleware->process($request, new OkHandler())->getStatusCode());
    }

    public function testNormalNestedKeyNamePasses(): void
    {
        $middleware = $this->createMiddleware(['mode' => 'block']);

        $request = $this->createRequest('POST', '/search', [
            'content-type' => 'application/json',
            'user-agent' => 'Mozilla/5.0',
        ], '{"query":{"operator":"and","fields":["title","tags"]}}');

        self::assertSame(200, $middleware->process($request, new OkHandler())->getStatusCode());
    }

    public function testChineseChatContentPasses(): void
    {
        $middleware = $this->createMiddleware(['mode' => 'block']);

        $request = $this->createRequest('POST', '/chat', [
            'content-type' => 'application/json',
            'user-agent' => 'Mozilla/5.0',
        ], '{"message":"请忽略以上噪音,我们继续讨论价格问题"}');

        self::assertSame(200, $middleware->process($request, new OkHandler())->getStatusCode());
    }
}
