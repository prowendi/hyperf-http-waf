<?php

declare(strict_types=1);

namespace Prowendi\HyperfHttpWaf\Support;

use Prowendi\HyperfHttpWaf\Contract\ReporterInterface;
use Prowendi\HyperfHttpWaf\Contract\RuleProviderInterface;
use Prowendi\HyperfHttpWaf\Decision\DecisionEngine;
use Prowendi\HyperfHttpWaf\Detector\BodyDetector;
use Prowendi\HyperfHttpWaf\Detector\CookieDetector;
use Prowendi\HyperfHttpWaf\Detector\FileUploadDetector;
use Prowendi\HyperfHttpWaf\Detector\HeaderDetector;
use Prowendi\HyperfHttpWaf\Detector\IpDetector;
use Prowendi\HyperfHttpWaf\Detector\MethodDetector;
use Prowendi\HyperfHttpWaf\Detector\PathDetector;
use Prowendi\HyperfHttpWaf\Detector\QueryDetector;
use Prowendi\HyperfHttpWaf\Detector\UaDetector;
use Prowendi\HyperfHttpWaf\Matcher\PatternMatcher;
use Prowendi\HyperfHttpWaf\Middleware\WafMiddleware;
use Psr\Container\ContainerInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;

final class WafMiddlewareFactory
{
    public function __invoke(ContainerInterface $container): WafMiddleware
    {
        $patternMatcher = new PatternMatcher();
        $ruleProvider = $container->get(RuleProviderInterface::class);

        $detectors = [
            'method' => new MethodDetector(),
            'ip' => new IpDetector(),
            'ua' => new UaDetector($patternMatcher, $ruleProvider),
            'path' => new PathDetector($patternMatcher, $ruleProvider),
            'query' => new QueryDetector($patternMatcher, $ruleProvider),
            'header' => new HeaderDetector($patternMatcher, $ruleProvider),
            'cookie' => new CookieDetector($patternMatcher, $ruleProvider),
            'body' => new BodyDetector($patternMatcher, $ruleProvider),
            'file_upload' => new FileUploadDetector(),
        ];

        return new WafMiddleware(
            new WafConfigFactory($container),
            new RequestContextFactory(),
            new AccessListMatcher(),
            $detectors,
            new DecisionEngine(),
            $container->get(ReporterInterface::class),
            new BlockingResponseFactory(
                $container->get(ResponseFactoryInterface::class),
                $container->get(StreamFactoryInterface::class),
            ),
        );
    }
}
