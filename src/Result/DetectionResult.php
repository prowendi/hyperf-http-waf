<?php

declare(strict_types=1);

namespace Prowendi\HyperfHttpWaf\Result;

use Prowendi\HyperfHttpWaf\Enum\DecisionAction;

final readonly class DetectionResult
{
    /**
     * @param list<RuleHit> $hitRules
     */
    public function __construct(
        public DecisionAction $action,
        public int $riskScore,
        public array $hitRules,
        public string $mode,
        public ?string $reason = null,
        public bool $whitelisted = false,
    ) {
    }

    public static function allow(string $mode, ?string $reason = null, bool $whitelisted = false): self
    {
        return new self(DecisionAction::Allow, 0, [], $mode, $reason, $whitelisted);
    }

    /**
     * @param list<RuleHit> $hitRules
     */
    public static function observe(int $riskScore, array $hitRules, string $mode, ?string $reason = null): self
    {
        return new self(DecisionAction::Observe, $riskScore, $hitRules, $mode, $reason);
    }

    /**
     * @param list<RuleHit> $hitRules
     */
    public static function block(int $riskScore, array $hitRules, string $mode, ?string $reason = null): self
    {
        return new self(DecisionAction::Block, $riskScore, $hitRules, $mode, $reason);
    }

    public function shouldReport(): bool
    {
        return $this->action !== DecisionAction::Allow;
    }

    public function toArray(): array
    {
        return [
            'action' => $this->action->value,
            'risk_score' => $this->riskScore,
            'mode' => $this->mode,
            'reason' => $this->reason,
            'whitelisted' => $this->whitelisted,
            'hit_rules' => array_map(static fn (RuleHit $hit): array => $hit->toArray(), $this->hitRules),
        ];
    }
}
