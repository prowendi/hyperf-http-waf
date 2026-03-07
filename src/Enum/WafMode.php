<?php

declare(strict_types=1);

namespace Prowendi\HyperfHttpWaf\Enum;

enum WafMode: string
{
    case Observe = 'observe';
    case Block = 'block';

    public static function fromString(string $value): self
    {
        return match (strtolower($value)) {
            'block' => self::Block,
            default => self::Observe,
        };
    }
}
