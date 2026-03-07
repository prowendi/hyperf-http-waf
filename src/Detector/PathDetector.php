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
use Prowendi\HyperfHttpWaf\Support\WildcardMatcher;

final class PathDetector implements DetectorInterface
{
    public function __construct(
        private readonly PatternMatcher $patternMatcher,
        private readonly RuleProviderInterface $ruleProvider,
        private readonly WildcardMatcher $wildcardMatcher = new WildcardMatcher(),
    ) {
    }

    public function detect(RequestContext $context, WafConfig $config): array
    {
        $hits = [];
        $lowerPath = strtolower($context->path);

        foreach ($config->sensitivePaths() as $candidate) {
            $candidate = strtolower($candidate);
            if ($candidate === '') {
                continue;
            }

            if (str_contains($lowerPath, $candidate) || $this->wildcardMatcher->matchesOne($context->path, $candidate)) {
                $hits[] = new RuleHit(
                    ruleId: 'path-sensitive-list',
                    name: 'Sensitive path access',
                    type: 'path',
                    target: 'path',
                    score: 85,
                    action: RuleAction::Block,
                    location: 'path:uri',
                    matchedSample: $context->path,
                );
                break;
            }
        }

        $rules = $this->ruleProvider->provide($config, ['path']);
        $hits = array_merge($hits, $this->patternMatcher->match([new TextInput('path', 'uri', $context->path)], $rules, $config));

        return $hits;
    }
}
