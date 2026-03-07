<?php

declare(strict_types=1);

namespace Prowendi\HyperfHttpWaf\Detector;

use Prowendi\HyperfHttpWaf\Config\WafConfig;
use Prowendi\HyperfHttpWaf\Contract\DetectorInterface;
use Prowendi\HyperfHttpWaf\Contract\RuleProviderInterface;
use Prowendi\HyperfHttpWaf\DTO\RequestContext;
use Prowendi\HyperfHttpWaf\Matcher\PatternMatcher;

final class CookieDetector implements DetectorInterface
{
    public function __construct(
        private readonly PatternMatcher $patternMatcher,
        private readonly RuleProviderInterface $ruleProvider,
    ) {
    }

    public function detect(RequestContext $context, WafConfig $config): array
    {
        if ($context->cookieInputs === []) {
            return [];
        }

        $rules = $this->ruleProvider->provide($config, ['cookie', 'input']);

        return $this->patternMatcher->match($context->cookieInputs, $rules, $config);
    }
}
