<?php

declare(strict_types=1);

namespace Prowendi\HyperfHttpWaf\Support;

final class CidrMatcher
{
    public function matches(string $ip, array $cidrs): bool
    {
        foreach ($cidrs as $cidr) {
            if ($this->matchesOne($ip, (string) $cidr)) {
                return true;
            }
        }

        return false;
    }

    public function matchesOne(string $ip, string $cidr): bool
    {
        $ip = trim($ip);
        $cidr = trim($cidr);
        if ($ip === '' || $cidr === '') {
            return false;
        }

        if (! str_contains($cidr, '/')) {
            return $ip === $cidr;
        }

        [$network, $mask] = explode('/', $cidr, 2);
        $ipBinary = @inet_pton($ip);
        $networkBinary = @inet_pton($network);
        if ($ipBinary === false || $networkBinary === false || strlen($ipBinary) !== strlen($networkBinary)) {
            return false;
        }

        $maxBits = strlen($ipBinary) * 8;
        $maskBits = (int) $mask;
        if ($maskBits < 0 || $maskBits > $maxBits) {
            return false;
        }

        $fullBytes = intdiv($maskBits, 8);
        $remainingBits = $maskBits % 8;

        if ($fullBytes > 0 && substr($ipBinary, 0, $fullBytes) !== substr($networkBinary, 0, $fullBytes)) {
            return false;
        }

        if ($remainingBits === 0) {
            return true;
        }

        $maskByte = (~((1 << (8 - $remainingBits)) - 1)) & 0xFF;

        return (ord($ipBinary[$fullBytes]) & $maskByte) === (ord($networkBinary[$fullBytes]) & $maskByte);
    }
}
