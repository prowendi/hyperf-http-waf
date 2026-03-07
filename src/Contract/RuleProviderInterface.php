<?php

declare(strict_types=1);

namespace Prowendi\HyperfHttpWaf\Contract;

use Prowendi\HyperfHttpWaf\Config\WafConfig;
use Prowendi\HyperfHttpWaf\DTO\Rule;

interface RuleProviderInterface
{
    /**
     * @param list<string> $targets
     * @return list<Rule>
     */
    public function provide(WafConfig $config, array $targets = []): array;
}
