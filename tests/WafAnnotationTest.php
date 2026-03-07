<?php

declare(strict_types=1);

namespace Prowendi\HyperfHttpWaf\Tests;

use Hyperf\HttpServer\Annotation\Middleware;
use Hyperf\HttpServer\PriorityMiddleware;
use Prowendi\HyperfHttpWaf\Annotation\Waf;
use Prowendi\HyperfHttpWaf\Middleware\WafMiddleware;

final class WafAnnotationTest extends TestCase
{
    public function testWafAnnotationExtendsHyperfMiddlewareAnnotation(): void
    {
        $annotation = new Waf();

        self::assertInstanceOf(Middleware::class, $annotation);
        self::assertSame(WafMiddleware::class, $annotation->middleware);
        self::assertSame(PriorityMiddleware::DEFAULT_PRIORITY, $annotation->priority);
    }

    public function testWafAnnotationAcceptsCustomPriority(): void
    {
        $annotation = new Waf(77);

        self::assertSame(WafMiddleware::class, $annotation->middleware);
        self::assertSame(77, $annotation->priority);
    }
}
