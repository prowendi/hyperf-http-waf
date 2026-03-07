<?php

declare(strict_types=1);

namespace Prowendi\HyperfHttpWaf\Tests;

use Prowendi\HyperfHttpWaf\Decision\DecisionEngine;
use Prowendi\HyperfHttpWaf\Decision\RiskScorer;
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
use Prowendi\HyperfHttpWaf\Support\AccessListMatcher;
use Prowendi\HyperfHttpWaf\Support\BlockingResponseFactory;
use Prowendi\HyperfHttpWaf\Support\CidrMatcher;
use Prowendi\HyperfHttpWaf\Support\ConfigRuleProvider;
use Prowendi\HyperfHttpWaf\Support\InputFlattener;
use Prowendi\HyperfHttpWaf\Support\RealIpResolver;
use Prowendi\HyperfHttpWaf\Support\RequestContextFactory;
use Prowendi\HyperfHttpWaf\Support\WafConfigFactory;
use Prowendi\HyperfHttpWaf\Support\WildcardMatcher;
use Prowendi\HyperfHttpWaf\Tests\Stubs\ArrayContainer;
use Prowendi\HyperfHttpWaf\Tests\Stubs\SpyReporter;
use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase as BaseTestCase;
use Psr\Http\Message\ServerRequestInterface;

abstract class TestCase extends BaseTestCase
{
    protected function createMiddleware(array $configOverrides = [], ?SpyReporter $reporter = null): WafMiddleware
    {
        $container = new ArrayContainer([
            'config' => [
                'waf' => $configOverrides,
            ],
        ]);

        $patternMatcher = new PatternMatcher();
        $ruleProvider = new ConfigRuleProvider();
        $psr17Factory = new Psr17Factory();
        $reporter ??= new SpyReporter();

        $detectors = [
            'method' => new MethodDetector(),
            'ip' => new IpDetector(),
            'ua' => new UaDetector($patternMatcher, $ruleProvider),
            'path' => new PathDetector($patternMatcher, $ruleProvider, new WildcardMatcher()),
            'query' => new QueryDetector($patternMatcher, $ruleProvider),
            'header' => new HeaderDetector($patternMatcher, $ruleProvider),
            'cookie' => new CookieDetector($patternMatcher, $ruleProvider),
            'body' => new BodyDetector($patternMatcher, $ruleProvider),
            'file_upload' => new FileUploadDetector(),
        ];

        return new WafMiddleware(
            new WafConfigFactory($container),
            new RequestContextFactory(new RealIpResolver(new CidrMatcher()), new InputFlattener()),
            new AccessListMatcher(new CidrMatcher(), new WildcardMatcher()),
            $detectors,
            new DecisionEngine(new RiskScorer()),
            $reporter,
            new BlockingResponseFactory($psr17Factory, $psr17Factory),
        );
    }

    protected function createRequest(
        string $method,
        string $uri,
        array $headers = [],
        ?string $body = null,
        array $serverParams = ['remote_addr' => '198.51.100.10']
    ): ServerRequestInterface {
        $request = new ServerRequest($method, $uri, $headers, $body ?? '', '1.1', $serverParams);
        if ($body !== null && ! isset($headers['content-type']) && ! isset($headers['Content-Type'])) {
            $request = $request->withHeader('content-type', 'text/plain');
        }

        return $request;
    }
}
