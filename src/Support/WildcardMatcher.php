<?php

declare(strict_types=1);

namespace Prowendi\HyperfHttpWaf\Support;

final class WildcardMatcher
{
    public function matches(string $value, array $patterns, bool $caseInsensitive = true): bool
    {
        foreach ($patterns as $pattern) {
            if ($this->matchesOne($value, (string) $pattern, $caseInsensitive)) {
                return true;
            }
        }

        return false;
    }

    public function matchesOne(string $value, string $pattern, bool $caseInsensitive = true): bool
    {
        if ($pattern === '') {
            return false;
        }

        if (strlen($pattern) > 2 && $pattern[0] === '/' && str_ends_with($pattern, '/')) {
            $result = preg_match($pattern . ($caseInsensitive ? 'i' : ''), $value);
            return $result === 1;
        }

        $quoted = preg_quote($pattern, '/');
        $quoted = str_replace('\*', '.*', $quoted);
        $regex = '/^' . $quoted . '$/' . ($caseInsensitive ? 'i' : '');
        $result = preg_match($regex, $value);

        return $result === 1;
    }
}
