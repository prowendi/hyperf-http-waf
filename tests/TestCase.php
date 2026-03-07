<?php

declare(strict_types=1);

namespace Prowendi\HyperfHttpWaf\Tests;

use Prowendi\HyperfHttpWaf\Contract\ReporterInterface;
use Prowendi\HyperfHttpWaf\Contract\RuleProviderInterface;
use Prowendi\HyperfHttpWaf\Decision\DecisionEngine;
use Prowendi\HyperfHttpWaf\Decision\RiskScorer;
use Prowendi\HyperfHttpWaf\Middleware\WafMiddleware;
use Prowendi\HyperfHttpWaf\Support\AccessListMatcher;
use Prowendi\HyperfHttpWaf\Support\CidrMatcher;
use Prowendi\HyperfHttpWaf\Support\ConfigRuleProvider;
use Prowendi\HyperfHttpWaf\Support\InputFlattener;
use Prowendi\HyperfHttpWaf\Support\RealIpResolver;
use Prowendi\HyperfHttpWaf\Support\RequestContextFactory;
use Prowendi\HyperfHttpWaf\Support\WafConfigFactory;
use Prowendi\HyperfHttpWaf\Support\WildcardMatcher;
use Prowendi\HyperfHttpWaf\Tests\Stubs\ArrayContainer;
use Prowendi\HyperfHttpWaf\Tests\Stubs\SpyReporter;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase as BaseTestCase;
use Psr\Http\Message\ServerRequestInterface;

abstract class TestCase extends BaseTestCase
{
    protected function createMiddleware(array $configOverrides = [], ?SpyReporter $reporter = null): WafMiddleware
    {
        $ruleProvider = new ConfigRuleProvider();
        $reporter ??= new SpyReporter();

        $container = new ArrayContainer([
            'config' => [
                'waf' => $configOverrides,
            ],
            RuleProviderInterface::class => $ruleProvider,
            ReporterInterface::class => $reporter,
        ]);

        return new WafMiddleware(
            new WafConfigFactory($container),
            new RequestContextFactory(new RealIpResolver(new CidrMatcher()), new InputFlattener()),
            new AccessListMatcher(new CidrMatcher(), new WildcardMatcher()),
            new DecisionEngine(new RiskScorer()),
            $container,
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
