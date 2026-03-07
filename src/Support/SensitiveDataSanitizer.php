<?php

declare(strict_types=1);

namespace Prowendi\HyperfHttpWaf\Support;

final class SensitiveDataSanitizer
{
    private const SENSITIVE_KEYS = [
        'password',
        'passwd',
        'token',
        'access_token',
        'refresh_token',
        'authorization',
        'cookie',
        'secret',
    ];

    public function sanitizeArray(array $payload, int $maxDepth = 10): array
    {
        return $this->doSanitize($payload, $maxDepth, 1);
    }

    private function doSanitize(array $payload, int $maxDepth, int $currentDepth): array
    {
        $sanitized = [];
        foreach ($payload as $key => $value) {
            $normalizedKey = strtolower((string) $key);
            if (in_array($normalizedKey, self::SENSITIVE_KEYS, true)) {
                $sanitized[$key] = '[redacted]';
                continue;
            }

            if (is_array($value)) {
                $sanitized[$key] = $currentDepth >= $maxDepth
                    ? '[nested:truncated]'
                    : $this->doSanitize($value, $maxDepth, $currentDepth + 1);
                continue;
            }

            if (is_string($value)) {
                $sanitized[$key] = $this->truncate($value, 512);
                continue;
            }

            $sanitized[$key] = $value;
        }

        return $sanitized;
    }

    public function truncate(?string $value, int $limit): ?string
    {
        if ($value === null) {
            return null;
        }

        if ($limit < 1 || strlen($value) <= $limit) {
            return $value;
        }

        return substr($value, 0, $limit) . '...';
    }
}
