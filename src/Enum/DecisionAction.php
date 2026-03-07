<?php

declare(strict_types=1);

namespace Prowendi\HyperfHttpWaf\Enum;

enum DecisionAction: string
{
    case Allow = 'allow';
    case Observe = 'observe';
    case Block = 'block';
}
