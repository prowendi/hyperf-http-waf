<?php

declare(strict_types=1);

namespace Prowendi\HyperfHttpWaf\Middleware;

use Prowendi\HyperfHttpWaf\Contract\DetectorInterface;
use Prowendi\HyperfHttpWaf\Contract\ReporterInterface;
use Prowendi\HyperfHttpWaf\Contract\RuleProviderInterface;
use Prowendi\HyperfHttpWaf\Config\WafConfig;
use Prowendi\HyperfHttpWaf\Decision\DecisionEngine;
use Prowendi\HyperfHttpWaf\Detector\BodyDetector;
use Prowendi\HyperfHttpWaf\Detector\CookieDetector;
use Prowendi\HyperfHttpWaf\Detector\FileUploadDetector;
use Prowendi\HyperfHttpWaf\Detector\HeaderDetector;
use Prowendi\HyperfHttpWaf\Detector\IpDetector;
use Prowendi\HyperfHttpWaf\Detector\MethodDetector;
use Prowendi\HyperfHttpWaf\Detector\PathDetector;
use Prowendi\HyperfHttpWaf\Detector\QueryDetector;
use Prowendi\HyperfHttpWaf\Detector\UaDetector;
use Prowendi\HyperfHttpWaf\DTO\RequestContext;
use Prowendi\HyperfHttpWaf\Enum\DecisionAction;
use Prowendi\HyperfHttpWaf\Enum\RuleAction;
use Prowendi\HyperfHttpWaf\Enum\WafMode;
use Prowendi\HyperfHttpWaf\Logger\LoggerReporter;
use Prowendi\HyperfHttpWaf\Matcher\PatternMatcher;
use Prowendi\HyperfHttpWaf\Result\RuleHit;
use Prowendi\HyperfHttpWaf\Support\AccessListMatcher;
use Prowendi\HyperfHttpWaf\Support\BlockingResponseFactory;
use Prowendi\HyperfHttpWaf\Support\ConfigRuleProvider;
use Prowendi\HyperfHttpWaf\Support\RequestContextFactory;
use Prowendi\HyperfHttpWaf\Support\WafConfigFactory;
use Psr\Container\ContainerInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

final class WafMiddleware implements MiddlewareInterface
{
    /**
     * @var array<string, DetectorInterface>
     */
    private readonly array $detectors;
    private readonly ReporterInterface $reporter;
    private readonly BlockingResponseFactory $blockingResponseFactory;

    public function __construct(
        private readonly WafConfigFactory $configFactory,
        private readonly RequestContextFactory $requestContextFactory,
        private readonly AccessListMatcher $accessListMatcher,
        private readonly DecisionEngine $decisionEngine,
        private readonly ContainerInterface $container,
        ?PatternMatcher $patternMatcher = null,
    ) {
        $patternMatcher ??= new PatternMatcher();
        $ruleProvider = $this->resolveRuleProvider();
        $this->reporter = $this->resolveReporter();
        $this->blockingResponseFactory = $this->resolveBlockingResponseFactory();
        $this->detectors = self::buildDetectors($patternMatcher, $ruleProvider);
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

        // In enforcing mode with block-on-first-match, the decision is
        // already fixed once a blocking hit exists, so skip the remaining
        // detectors. Observe mode always collects everything for reporting.
        $shortCircuit = $config->mode() === WafMode::Block && $config->blockOnFirstMatch();

        foreach ($this->detectors as $name => $detector) {
            if (! $config->detectorEnabled($name)) {
                continue;
            }

            array_push($hits, ...$detector->detect($context, $config));

            if ($shortCircuit) {
                foreach ($hits as $hit) {
                    if ($hit->action === RuleAction::Block) {
                        return $hits;
                    }
                }
            }
        }

        return $hits;
    }

    /**
     * @return array<string, DetectorInterface>
     */
    private static function buildDetectors(PatternMatcher $patternMatcher, RuleProviderInterface $ruleProvider): array
    {
        return [
            'method' => new MethodDetector(),
            'ip' => new IpDetector(),
            'ua' => new UaDetector($patternMatcher, $ruleProvider),
            'path' => new PathDetector($patternMatcher, $ruleProvider),
            'query' => new QueryDetector($patternMatcher, $ruleProvider),
            'header' => new HeaderDetector($patternMatcher, $ruleProvider),
            'cookie' => new CookieDetector($patternMatcher, $ruleProvider),
            'body' => new BodyDetector($patternMatcher, $ruleProvider),
            'file_upload' => new FileUploadDetector(),
        ];
    }

    private function resolveRuleProvider(): RuleProviderInterface
    {
        if ($this->container->has(RuleProviderInterface::class)) {
            $provider = $this->container->get(RuleProviderInterface::class);
            if ($provider instanceof RuleProviderInterface) {
                return $provider;
            }
        }

        if ($this->container->has(ConfigRuleProvider::class)) {
            $provider = $this->container->get(ConfigRuleProvider::class);
            if ($provider instanceof RuleProviderInterface) {
                return $provider;
            }
        }

        return new ConfigRuleProvider();
    }

    private function resolveReporter(): ReporterInterface
    {
        if ($this->container->has(ReporterInterface::class)) {
            $reporter = $this->container->get(ReporterInterface::class);
            if ($reporter instanceof ReporterInterface) {
                return $reporter;
            }
        }

        if ($this->container->has(LoggerReporter::class)) {
            $reporter = $this->container->get(LoggerReporter::class);
            if ($reporter instanceof ReporterInterface) {
                return $reporter;
            }
        }

        return new LoggerReporter($this->container);
    }

    private function resolveBlockingResponseFactory(): BlockingResponseFactory
    {
        if ($this->container->has(BlockingResponseFactory::class)) {
            $factory = $this->container->get(BlockingResponseFactory::class);
            if ($factory instanceof BlockingResponseFactory) {
                return $factory;
            }
        }

        return new BlockingResponseFactory();
    }
}
