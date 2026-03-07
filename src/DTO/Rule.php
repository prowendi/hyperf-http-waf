<?php

declare(strict_types=1);

namespace Prowendi\HyperfHttpWaf\DTO;

use Prowendi\HyperfHttpWaf\Enum\RuleAction;

final readonly class Rule
{
    /**
     * @param list<string> $prefilters
     */
    public function __construct(
        public string $ruleId,
        public string $name,
        public string $type,
        public string $target,
        public ?string $pattern,
        public array $prefilters,
        public int $score,
        public RuleAction $action,
        public bool $enabled = true,
    ) {
    }

    public static function fromArray(array $rule): self
    {
        return new self(
            (string) ($rule['rule_id'] ?? 'custom-rule'),
            (string) ($rule['name'] ?? 'Unnamed rule'),
            (string) ($rule['type'] ?? 'custom'),
            (string) ($rule['target'] ?? 'input'),
            isset($rule['pattern']) ? (string) $rule['pattern'] : null,
            array_values(array_map(static fn ($item): string => strtolower((string) $item), (array) ($rule['prefilters'] ?? []))),
            max(0, (int) ($rule['score'] ?? 0)),
            RuleAction::fromString((string) ($rule['action'] ?? 'score')),
            (bool) ($rule['enabled'] ?? true),
        );
    }
}
