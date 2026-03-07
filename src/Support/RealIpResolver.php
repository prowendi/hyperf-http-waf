<?php

declare(strict_types=1);

namespace Prowendi\HyperfHttpWaf\Support;

use Prowendi\HyperfHttpWaf\Config\WafConfig;
use Prowendi\HyperfHttpWaf\DTO\ResolvedIp;
use Psr\Http\Message\ServerRequestInterface;

final class RealIpResolver
{
    public function __construct(private readonly CidrMatcher $cidrMatcher = new CidrMatcher())
    {
    }

    public function resolve(ServerRequestInterface $request, WafConfig $config): ResolvedIp
    {
        $serverParams = $request->getServerParams();
        $remoteAddr = (string) ($serverParams['remote_addr'] ?? $serverParams['REMOTE_ADDR'] ?? '');
        if ($remoteAddr === '') {
            return new ResolvedIp('0.0.0.0', '0.0.0.0', 'unknown');
        }

        $trustedProxies = $config->trustedProxies();
        if (! $config->trustsAllProxies() && ($trustedProxies === [] || ! $this->cidrMatcher->matches($remoteAddr, $trustedProxies))) {
            return new ResolvedIp($remoteAddr, $remoteAddr, 'remote_addr');
        }

        foreach ($config->trustedHeaders() as $header) {
            $candidate = match ($header) {
                'x-forwarded-for' => $this->resolveFromXForwardedFor($request->getHeaderLine('x-forwarded-for'), $remoteAddr, $trustedProxies),
                'forwarded' => $this->resolveFromForwarded($request->getHeaderLine('forwarded'), $remoteAddr, $trustedProxies),
                default => $this->resolveSingleHeader($request->getHeaderLine($header)),
            };

            if ($candidate !== null) {
                return new ResolvedIp($candidate, $remoteAddr, $header);
            }
        }

        return new ResolvedIp($remoteAddr, $remoteAddr, 'remote_addr');
    }

    private function resolveSingleHeader(string $value): ?string
    {
        $value = trim($value);
        if ($value === '' || ! filter_var($value, FILTER_VALIDATE_IP)) {
            return null;
        }

        return $value;
    }

    private function resolveFromXForwardedFor(string $value, string $remoteAddr, array $trustedProxies): ?string
    {
        if ($value === '') {
            return null;
        }

        $chain = [];
        foreach (explode(',', $value) as $segment) {
            $ip = trim($segment);
            if ($ip === '' || ! filter_var($ip, FILTER_VALIDATE_IP)) {
                continue;
            }

            $chain[] = $ip;
        }

        if ($chain === []) {
            return null;
        }

        $chain[] = $remoteAddr;

        while ($chain !== [] && $this->cidrMatcher->matches(end($chain), $trustedProxies)) {
            array_pop($chain);
        }

        if ($chain === []) {
            return null;
        }

        return (string) end($chain);
    }

    private function resolveFromForwarded(string $value, string $remoteAddr, array $trustedProxies): ?string
    {
        if ($value === '') {
            return null;
        }

        preg_match_all('/for=(?:"?\\[?([a-f0-9:\\.]+)\\]?"?)/i', $value, $matches);
        $chain = [];
        foreach ($matches[1] ?? [] as $candidate) {
            $candidate = trim((string) $candidate);
            if ($candidate === '' || ! filter_var($candidate, FILTER_VALIDATE_IP)) {
                continue;
            }

            $chain[] = $candidate;
        }

        if ($chain === []) {
            return null;
        }

        $chain[] = $remoteAddr;

        while ($chain !== [] && $this->cidrMatcher->matches(end($chain), $trustedProxies)) {
            array_pop($chain);
        }

        if ($chain === []) {
            return null;
        }

        return (string) end($chain);
    }
}
