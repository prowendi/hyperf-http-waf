<?php

declare(strict_types=1);

namespace Prowendi\HyperfHttpWaf\Support;

use Prowendi\HyperfHttpWaf\Contract\ReporterInterface;
use Prowendi\HyperfHttpWaf\Contract\RuleProviderInterface;
use Prowendi\HyperfHttpWaf\Decision\DecisionEngine;
use Prowendi\HyperfHttpWaf\Middleware\WafMiddleware;
use Psr\Container\ContainerInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;

final class WafMiddlewareFactory
{
    public function __invoke(ContainerInterface $container): WafMiddleware
    {
        $ruleProvider = $container->get(RuleProviderInterface::class);

        return new WafMiddleware(
            new WafConfigFactory($container),
            new RequestContextFactory(),
            new AccessListMatcher(),
            $ruleProvider,
            new DecisionEngine(),
            $container->get(ReporterInterface::class),
            new BlockingResponseFactory(
                $container->get(ResponseFactoryInterface::class),
                $container->get(StreamFactoryInterface::class),
            ),
        );
    }
}
