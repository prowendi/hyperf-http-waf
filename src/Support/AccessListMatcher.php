<?php

declare(strict_types=1);

namespace Prowendi\HyperfHttpWaf\Support;

use Prowendi\HyperfHttpWaf\DTO\RequestContext;

final class AccessListMatcher
{
    public function __construct(
        private readonly CidrMatcher $cidrMatcher = new CidrMatcher(),
        private readonly WildcardMatcher $wildcardMatcher = new WildcardMatcher(),
    ) {
    }

    public function matchWhitelist(RequestContext $context, array $rules): ?string
    {
        return $this->match($context, $rules, 'whitelist');
    }

    public function matchBlacklist(RequestContext $context, array $rules): ?string
    {
        return $this->match($context, $rules, 'blacklist');
    }

    private function match(RequestContext $context, array $rules, string $prefix): ?string
    {
        $ips = array_values(array_map('strval', (array) ($rules['ips'] ?? [])));
        if (in_array($context->clientIp, $ips, true)) {
            return $prefix . '.ip';
        }

        $cidrs = array_values(array_map('strval', (array) ($rules['cidrs'] ?? [])));
        if ($cidrs !== [] && $this->cidrMatcher->matches($context->clientIp, $cidrs)) {
            return $prefix . '.cidr';
        }

        $paths = array_values(array_map('strval', (array) ($rules['paths'] ?? [])));
        if ($paths !== [] && $this->wildcardMatcher->matches($context->path, $paths)) {
            return $prefix . '.path';
        }

        $routes = array_values(array_map('strval', (array) ($rules['routes'] ?? [])));
        if ($context->routeName !== null && $routes !== [] && $this->wildcardMatcher->matches($context->routeName, $routes)) {
            return $prefix . '.route';
        }

        $headers = (array) ($rules['headers'] ?? []);
        foreach ($headers as $name => $patterns) {
            $values = $context->headers[strtolower((string) $name)] ?? [];
            foreach ($values as $value) {
                if ($this->matchesHeaderValue((string) $value, (array) $patterns)) {
                    return $prefix . '.header';
                }
            }
        }

        $userAgents = array_values(array_map('strval', (array) ($rules['user_agents'] ?? [])));
        if ($context->userAgent !== null && $userAgents !== [] && $this->matchesUserAgent($context->userAgent, $userAgents)) {
            return $prefix . '.ua';
        }

        return null;
    }

    private function matchesHeaderValue(string $value, array $patterns): bool
    {
        foreach ($patterns as $pattern) {
            $pattern = (string) $pattern;
            if ($pattern === '') {
                continue;
            }

            if ($this->wildcardMatcher->matchesOne($value, $pattern)) {
                return true;
            }

            if (stripos($value, $pattern) !== false) {
                return true;
            }
        }

        return false;
    }

    private function matchesUserAgent(string $value, array $patterns): bool
    {
        $normalized = strtolower($value);
        foreach ($patterns as $pattern) {
            $pattern = strtolower($pattern);
            if ($pattern === '') {
                continue;
            }

            if (str_contains($normalized, $pattern)) {
                return true;
            }

            if ($this->wildcardMatcher->matchesOne($value, $pattern)) {
                return true;
            }
        }

        return false;
    }
}
