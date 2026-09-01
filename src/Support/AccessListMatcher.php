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
        if ($paths !== []) {
            $variants = $this->pathVariants($context->path);

            // Whitelisting must hold for every interpretation of the path so
            // an encoded prefix cannot smuggle a request past the whitelist;
            // blacklisting flags the request when any interpretation hits.
            $matched = $prefix === 'whitelist'
                ? array_all($variants, fn (string $variant): bool => $this->wildcardMatcher->matches($variant, $paths))
                : array_any($variants, fn (string $variant): bool => $this->wildcardMatcher->matches($variant, $paths));

            if ($matched) {
                return $prefix . '.path';
            }
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

    /**
     * Whitelist/blacklist path patterns must hold against the path exactly
     * as the router will see it, not only the raw encoded form, otherwise an
     * encoded prefix could match a whitelist while the decoded path attacks.
     *
     * @return list<string>
     */
    private function pathVariants(string $path): array
    {
        $variants = [$path];

        $decoded = $path;
        for ($i = 0; $i < 3; $i++) {
            $next = rawurldecode($decoded);
            if ($next === $decoded) {
                break;
            }

            $decoded = $next;
        }

        foreach ([$decoded, $this->resolveDotSegments($decoded), $this->resolveDotSegments($path)] as $variant) {
            if ($variant !== '' && $variant !== '.') {
                $variants[] = $variant;
            }
        }

        return array_values(array_unique($variants));
    }

    /**
     * Lexically resolves ".", ".." and duplicate separators the same way a
     * router normalizes a request target ("/api/../.env" becomes "/.env").
     */
    private function resolveDotSegments(string $path): string
    {
        $leadingSlash = str_starts_with($path, '/');
        $trailingSlash = str_ends_with($path, '/');

        $resolved = [];
        foreach (explode('/', $path) as $segment) {
            if ($segment === '' || $segment === '.') {
                continue;
            }

            if ($segment === '..') {
                array_pop($resolved);
                continue;
            }

            $resolved[] = $segment;
        }

        $normalized = implode('/', $resolved);
        if ($leadingSlash) {
            $normalized = '/' . $normalized;
        }

        if ($trailingSlash && ! str_ends_with($normalized, '/')) {
            $normalized .= '/';
        }

        return $normalized;
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
