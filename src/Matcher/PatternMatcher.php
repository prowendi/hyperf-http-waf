<?php

declare(strict_types=1);

namespace Prowendi\HyperfHttpWaf\Matcher;

use Prowendi\HyperfHttpWaf\Config\WafConfig;
use Prowendi\HyperfHttpWaf\DTO\Rule;
use Prowendi\HyperfHttpWaf\DTO\TextInput;
use Prowendi\HyperfHttpWaf\Result\RuleHit;

final class PatternMatcher
{
    private const MAX_CANDIDATES = 64;

    public function match(array $inputs, array $rules, WafConfig $config): array
    {
        $hits = [];
        $seen = [];

        foreach ($inputs as $input) {
            $baseValue = trim($input->value);
            if ($baseValue === '') {
                continue;
            }

            foreach ($this->extractSlices($baseValue, $config->maxScanLength()) as $slice) {
                $candidates = $this->normalizeCandidates($slice, $config);
                if ($candidates === []) {
                    continue;
                }

                // Pre-lowercase each candidate once: the prefilter gate runs
                // for every (rule, candidate) pair and must not repeat the
                // strtolower work inside that loop. A list of pairs is used
                // because array keys would coerce numeric strings to ints.
                $prepared = [];
                foreach ($candidates as $candidate) {
                    $trimmed = trim((string) $candidate);
                    if ($trimmed !== '') {
                        $prepared[] = [$trimmed, strtolower($trimmed)];
                    }
                }

                foreach ($rules as $rule) {
                    $seenKey = $rule->ruleId . '|' . $input->label();
                    if (isset($seen[$seenKey])) {
                        continue;
                    }

                    $prefilters = array_map('strtolower', array_filter($rule->prefilters, static fn (string $p): bool => $p !== ''));

                    foreach ($prepared as [$candidate, $lowerCandidate]) {
                        if (! $this->passesPrefilters($lowerCandidate, $prefilters)) {
                            continue;
                        }

                        if ($rule->pattern !== null) {
                            $matched = preg_match($rule->pattern, $candidate);
                            if ($matched !== 1) {
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
        }

        return $hits;
    }

    /**
     * Large values are scanned at both the head and the tail so payloads
     * cannot hide behind a block of padding characters.
     *
     * @return list<string>
     */
    private function extractSlices(string $value, int $limit): array
    {
        if ($limit < 1 || strlen($value) <= $limit) {
            return [$value];
        }

        return [
            substr($value, 0, $limit),
            substr($value, -$limit),
        ];
    }

    /**
     * Builds every decoding/normalization variant of the value through a
     * converging pipeline: each stage consumes all candidates produced so
     * far, so combined obfuscations (version comments mixed with separator
     * tricks) still yield a fully-normalized candidate.
     *
     * @return list<string>
     */
    private function normalizeCandidates(string $value, WafConfig $config): array
    {
        $candidates = [$value];

        $candidates = $this->expand($candidates, fn (string $v): string => $this->urlDecodeStage($v, $config->urlDecodePasses()));

        if ($config->htmlEntityDecode()) {
            $candidates = $this->expand($candidates, static fn (string $v): string => html_entity_decode($v, ENT_QUOTES | ENT_HTML5, 'UTF-8'));
        }

        if ($config->base64Probe()) {
            $candidates = $this->expand($candidates, fn (string $v): string => $this->base64Stage($v));
        }

        // The two string-level normalizations must compose in both orders;
        // iterate until no new candidate appears (bounded).
        for ($round = 0; $round < 4; $round++) {
            $grown = $this->expand($candidates, fn (string $v): string => $this->normalizeSeparators($v));
            $grown = $this->expand($grown, fn (string $v): string => $this->stripVersionComments($v));

            if (count($grown) === count($candidates)) {
                break;
            }

            $candidates = $grown;
        }

        return array_values(array_filter($candidates, static fn (string $v): bool => trim($v) !== ''));
    }

    /**
     * @param list<string> $candidates
     * @param callable(string): string $stage
     * @return list<string>
     */
    private function expand(array $candidates, callable $stage): array
    {
        $out = [];
        foreach ($candidates as $candidate) {
            $out[$candidate] = $candidate;

            if (count($out) >= self::MAX_CANDIDATES) {
                break;
            }

            $transformed = $stage($candidate);
            if (is_string($transformed) && $transformed !== '' && $transformed !== $candidate) {
                $out[$transformed] = $transformed;
            }

            if (count($out) >= self::MAX_CANDIDATES) {
                break;
            }
        }

        return array_values($out);
    }

    private function urlDecodeStage(string $value, int $passes): string
    {
        $decoded = $value;
        for ($i = 0; $i < $passes; $i++) {
            $next = rawurldecode($decoded);
            if ($next === $decoded) {
                break;
            }

            $decoded = $next;
        }

        return $decoded;
    }

    private function base64Stage(string $candidate): string
    {
        if (! $this->looksLikeBase64($candidate)) {
            return $candidate;
        }

        $decoded = base64_decode($candidate, true);
        if (is_string($decoded) && $decoded !== '' && ! str_contains($decoded, "\0")) {
            return $decoded;
        }

        return $candidate;
    }

    /**
     * Prefilter gate: $candidate must already be lowercase; returns true
     * when any prefilter needle occurs in it.
     *
     * @param list<string> $prefilters
     */
    private function passesPrefilters(string $lowerCandidate, array $prefilters): bool
    {
        if ($prefilters === []) {
            return true;
        }

        foreach ($prefilters as $prefilter) {
            if ($prefilter !== '' && str_contains($lowerCandidate, $prefilter)) {
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

    /**
     * Collapses separator obfuscation so rules cannot be evaded with
     * variants such as "/etc/./passwd", "/etc//passwd" or overlong
     * UTF-8 encoded slashes. Both substitutions converge in a single
     * pass, keeping the cost linear per candidate.
     */
    private function normalizeSeparators(string $value): string
    {
        $value = strtr($value, [
            "\xc0\xaf" => '/',
            "\xe0\x80\xaf" => '/',
            "\xc0\x5c" => '\\',
            "\xe0\x80\x5c" => '\\',
        ]);

        $result = preg_replace(
            ['~(?<!:)/{2,}~', '~(?:/\.)/~'],
            ['/', '/'],
            $value
        );

        return is_string($result) ? $result : $value;
    }

    /**
     * MySQL version comments (backslash-star-bang prefixed blocks carrying a
     * version number before a keyword) hide keywords from word-boundary
     * patterns; strip the marker so the keyword is seen.
     */
    private function stripVersionComments(string $value): string
    {
        $result = preg_replace('~/\*!\d{0,6}\s*~i', '', $value);

        return is_string($result) ? $result : $value;
    }
}
