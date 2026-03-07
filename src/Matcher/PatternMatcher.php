<?php

declare(strict_types=1);

namespace Prowendi\HyperfHttpWaf\Matcher;

use Prowendi\HyperfHttpWaf\Config\WafConfig;
use Prowendi\HyperfHttpWaf\DTO\Rule;
use Prowendi\HyperfHttpWaf\DTO\TextInput;
use Prowendi\HyperfHttpWaf\Result\RuleHit;

final class PatternMatcher
{
    /**
     * @param list<TextInput> $inputs
     * @param list<Rule> $rules
     * @return list<RuleHit>
     */
    public function match(array $inputs, array $rules, WafConfig $config): array
    {
        $hits = [];
        $seen = [];

        foreach ($inputs as $input) {
            $baseValue = trim($input->value);
            if ($baseValue === '') {
                continue;
            }

            $candidates = $this->normalizeCandidates(substr($baseValue, 0, $config->maxScanLength()), $config);
            foreach ($rules as $rule) {
                $seenKey = $rule->ruleId . '|' . $input->label();
                if (isset($seen[$seenKey])) {
                    continue;
                }

                foreach ($candidates as $candidate) {
                    $candidate = $this->normalizeCandidate($candidate);
                    if ($candidate === '') {
                        continue;
                    }

                    if (! $this->passesPrefilters($candidate, $rule->prefilters)) {
                        continue;
                    }

                    if ($rule->pattern !== null) {
                        $matched = preg_match($rule->pattern, $candidate);
                        if ($matched === false) {
                            continue;
                        }
                        if ($matched === 0) {
                            continue;
                        }
                    }

                    $hits[] = new RuleHit(
                        ruleId: $rule->ruleId,
                        name: $rule->name,
                        type: $rule->type,
                        target: $rule->target,
                        score: $rule->score,
                        action: $rule->action,
                        location: $input->label(),
                        matchedSample: substr($candidate, 0, $config->matchedSampleLength()),
                    );
                    $seen[$seenKey] = true;
                    break;
                }
            }
        }

        return $hits;
    }

    /**
     * @return list<string>
     */
    private function normalizeCandidates(string $value, WafConfig $config): array
    {
        $queue = [$value];

        for ($i = 0; $i < $config->urlDecodePasses(); $i++) {
            $decoded = rawurldecode($queue[count($queue) - 1]);
            if ($decoded === $queue[count($queue) - 1]) {
                break;
            }

            $queue[] = $decoded;
        }

        $candidates = $queue;

        if ($config->htmlEntityDecode()) {
            foreach ($queue as $candidate) {
                $decoded = html_entity_decode($candidate, ENT_QUOTES | ENT_HTML5, 'UTF-8');
                if ($decoded !== $candidate) {
                    $candidates[] = $decoded;
                }
            }
        }

        if ($config->base64Probe()) {
            foreach ($queue as $candidate) {
                if (! $this->looksLikeBase64($candidate)) {
                    continue;
                }

                $decoded = base64_decode($candidate, true);
                if (is_string($decoded) && $decoded !== '' && ! str_contains($decoded, "\0")) {
                    $candidates[] = $decoded;
                }
            }
        }

        $unique = [];
        foreach ($candidates as $candidate) {
            $normalized = trim((string) $candidate);
            if ($normalized === '') {
                continue;
            }

            $unique[$normalized] = $normalized;
        }

        return array_values($unique);
    }

    /**
     * @param list<string> $prefilters
     */
    private function passesPrefilters(mixed $candidate, array $prefilters): bool
    {
        $candidate = $this->normalizeCandidate($candidate);
        if ($candidate === '') {
            return false;
        }

        if ($prefilters === []) {
            return true;
        }

        $normalized = strtolower($candidate);
        foreach ($prefilters as $prefilter) {
            if ($prefilter !== '' && str_contains($normalized, strtolower($prefilter))) {
                return true;
            }
        }

        return false;
    }

    private function looksLikeBase64(string $candidate): bool
    {
        $length = strlen($candidate);
        if ($length < 16 || $length > 1024) {
            return false;
        }

        return preg_match('/^[A-Za-z0-9+\/=]+$/', $candidate) === 1;
    }

    private function normalizeCandidate(mixed $candidate): string
    {
        if (is_string($candidate)) {
            return trim($candidate);
        }

        if (is_int($candidate) || is_float($candidate) || is_bool($candidate)) {
            return trim((string) $candidate);
        }

        if ($candidate instanceof \Stringable) {
            return trim((string) $candidate);
        }

        return '';
    }
}
