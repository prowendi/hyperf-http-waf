<?php

declare(strict_types=1);

namespace Prowendi\HyperfHttpWaf\Result;

use Prowendi\HyperfHttpWaf\Enum\RuleAction;

final readonly class RuleHit
{
    public function __construct(
        public string $ruleId,
        public string $name,
        public string $type,
        public string $target,
        public int $score,
        public RuleAction $action,
        public string $location,
        public ?string $matchedSample = null,
        public ?string $message = null,
    ) {
    }

    public function toArray(): array
    {
        return [
            'rule_id' => $this->ruleId,
            'name' => $this->name,
            'type' => $this->type,
            'target' => $this->target,
            'score' => $this->score,
            'action' => $this->action->value,
            'location' => $this->location,
            'matched_sample' => $this->matchedSample,
            'message' => $this->message,
        ];
    }
}
