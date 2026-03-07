<?php

declare(strict_types=1);

namespace Prowendi\HyperfHttpWaf\Tests;

use Prowendi\HyperfHttpWaf\Config\WafConfig;
use Prowendi\HyperfHttpWaf\Support\CidrMatcher;
use Prowendi\HyperfHttpWaf\Support\RealIpResolver;
use Nyholm\Psr7\ServerRequest;

final class RealIpResolverTest extends TestCase
{
    public function testTrustedProxyHeaderResolvesClientIp(): void
    {
        $request = new ServerRequest(
            'GET',
            '/proxy',
            ['x-forwarded-for' => '198.51.100.20, 10.0.0.12'],
            '',
            '1.1',
            ['remote_addr' => '10.0.0.11']
        );

        $resolver = new RealIpResolver(new CidrMatcher());
        $resolved = $resolver->resolve($request, WafConfig::fromArray([
            'trusted_proxies' => ['10.0.0.0/8'],
            'trusted_headers' => ['x-forwarded-for'],
        ]));

        self::assertSame('198.51.100.20', $resolved->clientIp);
        self::assertSame('10.0.0.11', $resolved->remoteAddr);
        self::assertSame('x-forwarded-for', $resolved->source);
    }
}
