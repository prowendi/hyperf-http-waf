<?php

declare(strict_types=1);

namespace Prowendi\HyperfHttpWaf\DTO;

final readonly class TextInput
{
    public function __construct(
        public string $location,
        public string $name,
        public string $value,
    ) {
    }

    public function label(): string
    {
        return $this->location . ':' . $this->name;
    }
}
