<?php

declare(strict_types=1);

namespace Prowendi\HyperfHttpWaf\Enum;

enum RuleAction: string
{
    case Score = 'score';
    case Block = 'block';

    public static function fromString(string $value): self
    {
        return match (strtolower($value)) {
            'block' => self::Block,
            default => self::Score,
        };
    }
}
