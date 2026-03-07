<?php

declare(strict_types=1);

namespace Prowendi\HyperfHttpWaf\Contract;

use Prowendi\HyperfHttpWaf\Config\WafConfig;
use Prowendi\HyperfHttpWaf\DTO\RequestContext;
use Prowendi\HyperfHttpWaf\Result\DetectionResult;

interface ReporterInterface
{
    public function report(RequestContext $context, DetectionResult $result, WafConfig $config): void;
}
