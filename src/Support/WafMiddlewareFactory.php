<?php

declare(strict_types=1);

namespace Prowendi\HyperfHttpWaf\Support;

use Prowendi\HyperfHttpWaf\Decision\DecisionEngine;
use Prowendi\HyperfHttpWaf\Middleware\WafMiddleware;
use Psr\Container\ContainerInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;

final class WafMiddlewareFactory
{
    public function __invoke(ContainerInterface $container): WafMiddleware
    {
        return new WafMiddleware(
            new WafConfigFactory($container),
            new RequestContextFactory(),
            new AccessListMatcher(),
            new DecisionEngine(),
            new BlockingResponseFactory(
                $container->get(ResponseFactoryInterface::class),
                $container->get(StreamFactoryInterface::class),
            ),
            $container,
        );
    }
}
