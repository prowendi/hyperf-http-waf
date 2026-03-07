<?php

declare(strict_types=1);

namespace Prowendi\HyperfHttpWaf\Contract;

use Prowendi\HyperfHttpWaf\Config\WafConfig;
use Prowendi\HyperfHttpWaf\DTO\RequestContext;
use Prowendi\HyperfHttpWaf\Result\RuleHit;

interface DetectorInterface
{
    /**
     * @return list<RuleHit>
     */
    public function detect(RequestContext $context, WafConfig $config): array;
}
