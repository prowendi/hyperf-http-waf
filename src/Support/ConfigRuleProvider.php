<?php

declare(strict_types=1);

namespace Prowendi\HyperfHttpWaf\Support;

use Prowendi\HyperfHttpWaf\Config\WafConfig;
use Prowendi\HyperfHttpWaf\Contract\RuleProviderInterface;
use Prowendi\HyperfHttpWaf\DTO\Rule;

final class ConfigRuleProvider implements RuleProviderInterface
{
    /** @var array<string, list<Rule>> */
    private array $cache = [];

    /** @var list<Rule>|null */
    private ?array $allRules = null;

    public function provide(WafConfig $config, array $targets = []): array
    {
        $key = $targets === [] ? '*' : implode('|', $targets);
        if (isset($this->cache[$key])) {
            return $this->cache[$key];
        }

        $allRules = $this->resolveAllRules($config);
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
        $this->allRules = null;
    }

    /**
     * @return list<Rule>
     */
    private function resolveAllRules(WafConfig $config): array
    {
        if ($this->allRules !== null) {
            return $this->allRules;
        }

        $rules = [];
        foreach ($config->rules() as $rule) {
            $candidate = Rule::fromArray((array) $rule);
            if (! $candidate->enabled) {
                continue;
            }
            $rules[] = $candidate;
        }

        return $this->allRules = $rules;
    }
}
