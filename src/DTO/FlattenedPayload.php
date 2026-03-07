<?php

declare(strict_types=1);

namespace Prowendi\HyperfHttpWaf\DTO;

final readonly class FlattenedPayload
{
    /**
     * @param list<TextInput> $inputs
     */
    public function __construct(
        public array $inputs,
        public int $count,
        public int $maxDepth,
        public int $maxValueLength,
    ) {
    }
}
