<?php

declare(strict_types=1);

namespace Prowendi\HyperfHttpWaf\Detector;

use Prowendi\HyperfHttpWaf\Config\WafConfig;
use Prowendi\HyperfHttpWaf\Contract\DetectorInterface;
use Prowendi\HyperfHttpWaf\Contract\RuleProviderInterface;
use Prowendi\HyperfHttpWaf\DTO\RequestContext;
use Prowendi\HyperfHttpWaf\Enum\RuleAction;
use Prowendi\HyperfHttpWaf\Matcher\PatternMatcher;
use Prowendi\HyperfHttpWaf\Result\RuleHit;

final class HeaderDetector implements DetectorInterface
{
    public function __construct(
        private readonly PatternMatcher $patternMatcher,
        private readonly RuleProviderInterface $ruleProvider,
    ) {
    }

    public function detect(RequestContext $context, WafConfig $config): array
    {
        $hits = [];

        foreach ($context->headers as $name => $values) {
            foreach ($values as $value) {
                if (strlen($value) > $config->maxHeaderValueLength()) {
                    $hits[] = new RuleHit(
                        ruleId: 'header-value-length',
                        name: 'Header value length exceeded',
                        type: 'shape',
                        target: 'header',
                        score: 20,
                        action: RuleAction::Score,
                        location: 'header:' . $name,
                        matchedSample: $name,
                    );
                    break 2;
                }
            }
        }

        $rules = $this->ruleProvider->provide($config, ['header', 'input']);

        return array_merge($hits, $this->patternMatcher->match($context->headerInputs, $rules, $config));
    }
}
