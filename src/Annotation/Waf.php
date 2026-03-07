<?php

declare(strict_types=1);

namespace Prowendi\HyperfHttpWaf\Annotation;

use Attribute;
use Hyperf\HttpServer\Annotation\Middleware;
use Hyperf\HttpServer\PriorityMiddleware;
use Prowendi\HyperfHttpWaf\Middleware\WafMiddleware;

#[Attribute(Attribute::TARGET_CLASS | Attribute::TARGET_METHOD)]
final class Waf extends Middleware
{
    public function __construct(int $priority = PriorityMiddleware::DEFAULT_PRIORITY)
    {
        parent::__construct(WafMiddleware::class, $priority);
    }
}
