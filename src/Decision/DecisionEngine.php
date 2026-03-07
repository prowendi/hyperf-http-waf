<?php

declare(strict_types=1);

namespace Prowendi\HyperfHttpWaf\Decision;

use Prowendi\HyperfHttpWaf\Config\WafConfig;
use Prowendi\HyperfHttpWaf\DTO\RequestContext;
use Prowendi\HyperfHttpWaf\Enum\RuleAction;
use Prowendi\HyperfHttpWaf\Enum\WafMode;
use Prowendi\HyperfHttpWaf\Result\DetectionResult;
use Prowendi\HyperfHttpWaf\Result\RuleHit;

final class DecisionEngine
{
    public function __construct(private readonly RiskScorer $riskScorer = new RiskScorer())
    {
    }

    /**
     * @param list<RuleHit> $hits
     */
    public function decide(RequestContext $context, array $hits, WafConfig $config): DetectionResult
    {
        $mode = $config->mode();

        if ($hits === []) {
            return DetectionResult::allow($mode->value);
        }

        $riskScore = $this->riskScorer->score($hits);
        $blockHit = $this->hasBlockHit($hits);

        if ($mode === WafMode::Observe) {
            return DetectionResult::observe($riskScore, $hits, $mode->value, 'observe_mode');
        }

        if ($config->blockOnFirstMatch() && $blockHit) {
            return DetectionResult::block($riskScore, $hits, $mode->value, 'block_rule_hit');
        }

        if ($riskScore >= $config->scoreThreshold()) {
            return DetectionResult::block($riskScore, $hits, $mode->value, 'score_threshold');
        }

        return DetectionResult::observe($riskScore, $hits, $mode->value, 'below_threshold');
    }

    /**
     * @param list<RuleHit> $hits
     */
    private function hasBlockHit(array $hits): bool
    {
        foreach ($hits as $hit) {
            if ($hit->action === RuleAction::Block) {
                return true;
            }
        }

        return false;
    }
}
