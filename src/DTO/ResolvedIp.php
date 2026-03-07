<?php

declare(strict_types=1);

namespace Prowendi\HyperfHttpWaf\DTO;

final readonly class ResolvedIp
{
    public function __construct(
        public string $clientIp,
        public string $remoteAddr,
        public string $source,
    ) {
    }
}
