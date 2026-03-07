<?php

declare(strict_types=1);

namespace Prowendi\HyperfHttpWaf\Tests\Stubs;

use Prowendi\HyperfHttpWaf\Config\WafConfig;
use Prowendi\HyperfHttpWaf\Contract\ReporterInterface;
use Prowendi\HyperfHttpWaf\DTO\RequestContext;
use Prowendi\HyperfHttpWaf\Result\DetectionResult;

final class SpyReporter implements ReporterInterface
{
    /**
     * @var list<array{context: RequestContext, result: DetectionResult, config: WafConfig}>
     */
    public array $entries = [];

    public function report(RequestContext $context, DetectionResult $result, WafConfig $config): void
    {
        $this->entries[] = [
            'context' => $context,
            'result' => $result,
            'config' => $config,
        ];
    }
}
