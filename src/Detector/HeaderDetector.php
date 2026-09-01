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

        $hostHit = $this->detectHostAnomaly($context);
        if ($hostHit !== null) {
            $hits[] = $hostHit;
        }

        $underscoreHit = $this->detectUnderscoreForwardHeader($context);
        if ($underscoreHit !== null) {
            $hits[] = $underscoreHit;
        }

        $rules = $this->ruleProvider->provide($config, ['header', 'input']);

        return array_merge($hits, $this->patternMatcher->match($context->headerInputs, $rules, $config));
    }

    /**
     * Host values carrying path/query fragments ("target:8080/?") are used
     * to bypass origin- or host-keyed validation upstream.
     */
    private function detectHostAnomaly(RequestContext $context): ?RuleHit
    {
        foreach ($context->headers['host'] ?? [] as $host) {
            if (preg_match('~[/?#\\\\]~', $host) === 1) {
                return new RuleHit(
                    ruleId: 'header-host-anomaly',
                    name: 'Suspicious Host header value',
                    type: 'header',
                    target: 'header',
                    score: 30,
                    action: RuleAction::Score,
                    location: 'header:host',
                    matchedSample: substr($host, 0, 120),
                );
            }
        }

        return null;
    }

    /**
     * Underscore variants of forwarding headers ("X-Forwarded-For" sent as
     * "X_Forwarded_For") attempt to slip spoofed client IPs past proxies
     * that only sanitize the hyphenated spelling.
     */
    private function detectUnderscoreForwardHeader(RequestContext $context): ?RuleHit
    {
        foreach (['x_forwarded_for', 'x_real_ip', 'x_forwarded_host'] as $name) {
            if (($context->headers[$name] ?? []) !== []) {
                return new RuleHit(
                    ruleId: 'header-underscore-forward',
                    name: 'Underscore forwarding header variant',
                    type: 'header',
                    target: 'header',
                    score: 20,
                    action: RuleAction::Score,
                    location: 'header:' . $name,
                    matchedSample: $name,
                );
            }
        }

        return null;
    }
}
