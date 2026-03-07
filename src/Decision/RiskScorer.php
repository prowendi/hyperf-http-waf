<?php

declare(strict_types=1);

namespace Prowendi\HyperfHttpWaf\Decision;

use Prowendi\HyperfHttpWaf\Result\RuleHit;

final class RiskScorer
{
    /**
     * @param list<RuleHit> $hits
     */
    public function score(array $hits): int
    {
        $byRule = [];
        foreach ($hits as $hit) {
            $byRule[$hit->ruleId] = max($byRule[$hit->ruleId] ?? 0, $hit->score);
        }

        return array_sum($byRule);
    }
}
