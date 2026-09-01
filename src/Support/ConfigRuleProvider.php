<?php

declare(strict_types=1);

namespace Prowendi\HyperfHttpWaf\Support;

use Prowendi\HyperfHttpWaf\Config\WafConfig;
use Prowendi\HyperfHttpWaf\Contract\RuleProviderInterface;
use Prowendi\HyperfHttpWaf\DTO\Rule;

final class ConfigRuleProvider implements RuleProviderInterface
{
    /**
     * Provider instances are usually container singles while WafConfig is
     * rebuilt per request, so every cache entry is keyed by the rule source
     * content — a config-center hot reload must never serve stale rules.
     *
     * @var array<string, list<Rule>>
     */
    private array $cache = [];

    /** @var array<string, list<Rule>> */
    private array $allRules = [];

    public function provide(WafConfig $config, array $targets = []): array
    {
        $sourceKey = md5(serialize($config->rules()));
        $key = ($targets === [] ? '*' : implode('|', $targets)) . '@' . $sourceKey;
        if (isset($this->cache[$key])) {
            return $this->cache[$key];
        }

        $allRules = $this->resolveAllRules($config, $sourceKey);
        if ($targets === []) {
            return $this->cache[$key] = $allRules;
        }

        $filtered = [];
        foreach ($allRules as $rule) {
            if (in_array($rule->target, $targets, true)) {
                $filtered[] = $rule;
            }
        }

        return $this->cache[$key] = $filtered;
    }

    public function reset(): void
    {
        $this->cache = [];
        $this->allRules = [];
    }

    /**
     * @return list<Rule>
     */
    private function resolveAllRules(WafConfig $config, string $sourceKey): array
    {
        if (isset($this->allRules[$sourceKey])) {
            return $this->allRules[$sourceKey];
        }

        $rules = [];
        foreach ($config->rules() as $rule) {
            $candidate = Rule::fromArray((array) $rule);
            if (! $candidate->enabled) {
                continue;
            }
            $rules[] = $candidate;
        }

        return $this->allRules[$sourceKey] = $rules;
    }
}
