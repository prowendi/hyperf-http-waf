<?php

declare(strict_types=1);

namespace Prowendi\HyperfHttpWaf\Detector;

use Prowendi\HyperfHttpWaf\Config\WafConfig;
use Prowendi\HyperfHttpWaf\Contract\DetectorInterface;
use Prowendi\HyperfHttpWaf\Contract\RuleProviderInterface;
use Prowendi\HyperfHttpWaf\DTO\RequestContext;
use Prowendi\HyperfHttpWaf\DTO\TextInput;
use Prowendi\HyperfHttpWaf\Enum\RuleAction;
use Prowendi\HyperfHttpWaf\Matcher\PatternMatcher;
use Prowendi\HyperfHttpWaf\Result\RuleHit;

final class UaDetector implements DetectorInterface
{
    public function __construct(
        private readonly PatternMatcher $patternMatcher,
        private readonly RuleProviderInterface $ruleProvider,
    ) {
    }

    public function detect(RequestContext $context, WafConfig $config): array
    {
        if ($context->userAgent === null || $context->userAgent === '') {
            return [];
        }

        $hits = [];
        $normalized = strtolower($context->userAgent);
        foreach ($config->badUserAgents() as $needle) {
            if ($needle !== '' && str_contains($normalized, $needle)) {
                $hits[] = new RuleHit(
                    ruleId: 'ua-bad-agent',
                    name: 'Known scanner user agent',
                    type: 'ua',
                    target: 'ua',
                    score: 65,
                    action: RuleAction::Block,
                    location: 'header:user-agent',
                    matchedSample: substr($context->userAgent, 0, $config->matchedSampleLength()),
                );
                break;
            }
        }

        $inputs = [new TextInput('ua', 'user-agent', $context->userAgent)];
        $rules = $this->ruleProvider->provide($config, ['ua']);

        return array_merge($hits, $this->patternMatcher->match($inputs, $rules, $config));
    }
}
