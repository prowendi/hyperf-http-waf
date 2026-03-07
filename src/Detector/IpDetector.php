<?php

declare(strict_types=1);

namespace Prowendi\HyperfHttpWaf\Detector;

use Prowendi\HyperfHttpWaf\Config\WafConfig;
use Prowendi\HyperfHttpWaf\Contract\DetectorInterface;
use Prowendi\HyperfHttpWaf\DTO\RequestContext;
use Prowendi\HyperfHttpWaf\Enum\RuleAction;
use Prowendi\HyperfHttpWaf\Result\RuleHit;

final class IpDetector implements DetectorInterface
{
    public function detect(RequestContext $context, WafConfig $config): array
    {
        $hits = [];

        if (! filter_var($context->clientIp, FILTER_VALIDATE_IP)) {
            $hits[] = new RuleHit(
                ruleId: 'ip-invalid',
                name: 'Invalid client IP',
                type: 'ip',
                target: 'ip',
                score: 90,
                action: RuleAction::Block,
                location: 'client_ip',
                matchedSample: $context->clientIp,
            );
        }

        $forwardHeaders = ['x-forwarded-for', 'x-real-ip', 'forwarded'];
        $hasForwardHeader = false;
        foreach ($forwardHeaders as $header) {
            if (($context->headers[$header] ?? []) !== []) {
                $hasForwardHeader = true;
                break;
            }
        }

        if ($hasForwardHeader && $context->ipSource === 'remote_addr' && $config->trustedProxies() === []) {
            $hits[] = new RuleHit(
                ruleId: 'ip-untrusted-forward-header',
                name: 'Forwarding headers from untrusted source',
                type: 'ip',
                target: 'header',
                score: 20,
                action: RuleAction::Score,
                location: 'header:forwarding',
                matchedSample: 'forwarding headers present',
            );
        }

        return $hits;
    }
}
