<?php

declare(strict_types=1);

namespace Prowendi\HyperfHttpWaf\Detector;

use Prowendi\HyperfHttpWaf\Config\WafConfig;
use Prowendi\HyperfHttpWaf\Contract\DetectorInterface;
use Prowendi\HyperfHttpWaf\DTO\RequestContext;
use Prowendi\HyperfHttpWaf\Enum\RuleAction;
use Prowendi\HyperfHttpWaf\Result\RuleHit;

final class MethodDetector implements DetectorInterface
{
    public function detect(RequestContext $context, WafConfig $config): array
    {
        if (in_array($context->method, $config->allowedMethods(), true)) {
            return [];
        }

        return [
            new RuleHit(
                ruleId: 'method-illegal',
                name: 'Illegal HTTP method',
                type: 'method',
                target: 'method',
                score: 100,
                action: RuleAction::Block,
                location: 'method',
                matchedSample: $context->method,
            ),
        ];
    }
}
