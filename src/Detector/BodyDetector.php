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

final class BodyDetector implements DetectorInterface
{
    public function __construct(
        private readonly PatternMatcher $patternMatcher,
        private readonly RuleProviderInterface $ruleProvider,
    ) {
    }

    public function detect(RequestContext $context, WafConfig $config): array
    {
        $hits = [];

        if ($context->bodyTooLarge) {
            $hits[] = new RuleHit(
                ruleId: 'body-size-limit',
                name: 'Body inspection size limit exceeded',
                type: 'shape',
                target: 'body',
                score: 30,
                action: RuleAction::Score,
                location: 'body',
                matchedSample: (string) $context->bodySize,
            );
        }

        if ($context->bodyParseFailed) {
            $hits[] = new RuleHit(
                ruleId: 'body-json-parse-failed',
                name: 'Malformed JSON body',
                type: 'shape',
                target: 'body',
                score: 10,
                action: RuleAction::Score,
                location: 'body',
                matchedSample: 'json_parse_failed',
            );
        }

        if ($context->bodyParameterCount > $config->maxParameterCount('body')) {
            $hits[] = new RuleHit(
                ruleId: 'body-parameter-count',
                name: 'Body parameter count exceeded',
                type: 'shape',
                target: 'body',
                score: 30,
                action: RuleAction::Score,
                location: 'body',
                matchedSample: (string) $context->bodyParameterCount,
            );
        }

        if ($context->bodyMaxDepth > $config->maxNestedDepth()) {
            $hits[] = new RuleHit(
                ruleId: 'body-depth',
                name: 'Body nesting depth exceeded',
                type: 'shape',
                target: 'body',
                score: 30,
                action: RuleAction::Score,
                location: 'body',
                matchedSample: (string) $context->bodyMaxDepth,
            );
        }

        if ($context->bodyMaxValueLength > $config->maxValueLength()) {
            $hits[] = new RuleHit(
                ruleId: 'body-value-length',
                name: 'Body value length exceeded',
                type: 'shape',
                target: 'body',
                score: 25,
                action: RuleAction::Score,
                location: 'body',
                matchedSample: (string) $context->bodyMaxValueLength,
            );
        }

        if ($context->bodyInputs === []) {
            return $hits;
        }

        $rules = $this->ruleProvider->provide($config, ['body', 'input']);

        return array_merge($hits, $this->patternMatcher->match($context->bodyInputs, $rules, $config));
    }
}
