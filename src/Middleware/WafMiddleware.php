<?php

declare(strict_types=1);

namespace Prowendi\HyperfHttpWaf\Middleware;

use Prowendi\HyperfHttpWaf\Contract\DetectorInterface;
use Prowendi\HyperfHttpWaf\Contract\ReporterInterface;
use Prowendi\HyperfHttpWaf\Config\WafConfig;
use Prowendi\HyperfHttpWaf\Decision\DecisionEngine;
use Prowendi\HyperfHttpWaf\DTO\RequestContext;
use Prowendi\HyperfHttpWaf\Enum\DecisionAction;
use Prowendi\HyperfHttpWaf\Enum\RuleAction;
use Prowendi\HyperfHttpWaf\Result\RuleHit;
use Prowendi\HyperfHttpWaf\Support\AccessListMatcher;
use Prowendi\HyperfHttpWaf\Support\BlockingResponseFactory;
use Prowendi\HyperfHttpWaf\Support\RequestContextFactory;
use Prowendi\HyperfHttpWaf\Support\WafConfigFactory;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

final class WafMiddleware implements MiddlewareInterface
{
    /**
     * @param array<string, DetectorInterface> $detectors
     */
    public function __construct(
        private readonly WafConfigFactory $configFactory,
        private readonly RequestContextFactory $requestContextFactory,
        private readonly AccessListMatcher $accessListMatcher,
        private readonly array $detectors,
        private readonly DecisionEngine $decisionEngine,
        private readonly ReporterInterface $reporter,
        private readonly BlockingResponseFactory $blockingResponseFactory,
    ) {
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $config = $this->configFactory->create();
        if (! $config->enabled()) {
            return $handler->handle($request);
        }

        $context = $this->requestContextFactory->create($request, $config);
        $whitelistReason = $this->accessListMatcher->matchWhitelist($context, $config->whitelist());
        if ($whitelistReason !== null) {
            return $handler->handle($request);
        }

        $hits = [];
        $blacklistReason = $this->accessListMatcher->matchBlacklist($context, $config->blacklist());
        if ($blacklistReason !== null) {
            $hits[] = new RuleHit(
                ruleId: 'request-blacklist',
                name: 'Configured blacklist match',
                type: 'blacklist',
                target: 'request',
                score: 100,
                action: RuleAction::Block,
                location: $blacklistReason,
                matchedSample: $context->path,
            );
        } else {
            $hits = $this->collectHits($context, $config);
        }

        $result = $this->decisionEngine->decide($context, $hits, $config);
        if ($result->shouldReport()) {
            $this->reporter->report($context, $result, $config);
        }

        if ($result->action === DecisionAction::Block) {
            return $this->blockingResponseFactory->create($result, $config);
        }

        return $handler->handle($request);
    }

    /**
     * @return list<RuleHit>
     */
    private function collectHits(RequestContext $context, WafConfig $config): array
    {
        $hits = [];

        foreach ($this->detectors as $name => $detector) {
            if ($config->detectorEnabled($name)) {
                array_push($hits, ...$detector->detect($context, $config));
            }
        }

        return $hits;
    }
}
