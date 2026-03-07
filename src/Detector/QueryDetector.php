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

final class QueryDetector implements DetectorInterface
{
    public function __construct(
        private readonly PatternMatcher $patternMatcher,
        private readonly RuleProviderInterface $ruleProvider,
    ) {
    }

    public function detect(RequestContext $context, WafConfig $config): array
    {
        $hits = [];

        if ($context->queryParameterCount > $config->maxParameterCount('query')) {
            $hits[] = new RuleHit(
                ruleId: 'query-parameter-count',
                name: 'Query parameter count exceeded',
                type: 'shape',
                target: 'query',
                score: 30,
                action: RuleAction::Score,
                location: 'query',
                matchedSample: (string) $context->queryParameterCount,
            );
        }

        if ($context->queryMaxDepth > $config->maxNestedDepth()) {
            $hits[] = new RuleHit(
                ruleId: 'query-depth',
                name: 'Query nesting depth exceeded',
                type: 'shape',
                target: 'query',
                score: 30,
                action: RuleAction::Score,
                location: 'query',
                matchedSample: (string) $context->queryMaxDepth,
            );
        }

        if ($context->queryMaxValueLength > $config->maxValueLength()) {
            $hits[] = new RuleHit(
                ruleId: 'query-value-length',
                name: 'Query value length exceeded',
                type: 'shape',
                target: 'query',
                score: 25,
                action: RuleAction::Score,
                location: 'query',
                matchedSample: (string) $context->queryMaxValueLength,
            );
        }

        $rules = $this->ruleProvider->provide($config, ['query', 'input']);

        return array_merge($hits, $this->patternMatcher->match($context->queryInputs, $rules, $config));
    }
}
