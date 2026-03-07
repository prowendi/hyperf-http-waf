<?php

declare(strict_types=1);

namespace Prowendi\HyperfHttpWaf\Logger;

use Prowendi\HyperfHttpWaf\Config\WafConfig;
use Prowendi\HyperfHttpWaf\Contract\ReporterInterface;
use Prowendi\HyperfHttpWaf\DTO\RequestContext;
use Prowendi\HyperfHttpWaf\DTO\UploadedFileMetadata;
use Prowendi\HyperfHttpWaf\Enum\DecisionAction;
use Prowendi\HyperfHttpWaf\Result\DetectionResult;
use Prowendi\HyperfHttpWaf\Result\RuleHit;
use Prowendi\HyperfHttpWaf\Support\SensitiveDataSanitizer;
use Psr\Container\ContainerInterface;
use Psr\Log\LoggerInterface;

final class LoggerReporter implements ReporterInterface
{
    public function __construct(
        private readonly ContainerInterface $container,
        private readonly SensitiveDataSanitizer $sanitizer = new SensitiveDataSanitizer(),
    ) {
    }

    public function report(RequestContext $context, DetectionResult $result, WafConfig $config): void
    {
        if (! $config->loggingEnabled()) {
            return;
        }

        $payload = [
            'time' => gmdate('c'),
            'client_ip' => $context->clientIp,
            'remote_addr' => $context->remoteAddr,
            'ip_source' => $context->ipSource,
            'method' => $context->method,
            'path' => $context->path,
            'route' => $context->routeName,
            'action' => $result->action->value,
            'risk_score' => $result->riskScore,
            'mode' => $result->mode,
            'reason' => $result->reason,
            'hit_rules' => array_map(static fn (RuleHit $hit): string => $hit->ruleId, $result->hitRules),
            'hits' => array_map(
                fn (RuleHit $hit): array => [
                    'rule_id' => $hit->ruleId,
                    'type' => $hit->type,
                    'target' => $hit->target,
                    'score' => $hit->score,
                    'location' => $hit->location,
                    'sample' => $this->sanitizer->truncate($hit->matchedSample, $config->matchedSampleLength()),
                ],
                $result->hitRules
            ),
            'ua' => $this->sanitizer->truncate($context->userAgent, $config->uaMaxLength()),
            'referer' => $this->sanitizer->truncate($context->referer, 512),
            'request' => [
                'query' => $this->sanitizer->sanitizeArray($context->queryParams),
                'headers' => $this->sanitizer->sanitizeArray($context->headers),
                'cookies' => $this->sanitizer->sanitizeArray($context->cookies),
                'body' => $this->buildBodyLog($context, $config),
                'files' => array_map(static fn (UploadedFileMetadata $file): array => $file->toArray(), $context->files),
            ],
        ];

        $logger = $this->resolveLogger($config);
        if ($logger instanceof LoggerInterface) {
            $level = $result->action === DecisionAction::Block ? 'warning' : 'notice';
            $logger->log($level, 'hyperf_http_waf', $payload);
            return;
        }

        $encoded = json_encode([
            'message' => 'hyperf_http_waf',
            'context' => $payload,
        ], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);

        if (is_string($encoded)) {
            error_log($encoded);
        }
    }

    private function buildBodyLog(RequestContext $context, WafConfig $config): array|string|null
    {
        if ($context->bodyParams !== []) {
            return $this->sanitizer->sanitizeArray($context->bodyParams);
        }

        if ($context->rawBody !== null) {
            return $this->sanitizer->truncate($context->rawBody, $config->logBodyMaxLength());
        }

        return null;
    }

    private function resolveLogger(WafConfig $config): ?LoggerInterface
    {
        $channel = $config->loggingChannel();
        $loggerFactoryClass = 'Hyperf\\Logger\\LoggerFactory';
        if ($channel !== null && class_exists($loggerFactoryClass) && $this->container->has($loggerFactoryClass)) {
            $factory = $this->container->get($loggerFactoryClass);
            if (is_object($factory) && method_exists($factory, 'get')) {
                $logger = $factory->get($channel);
                if ($logger instanceof LoggerInterface) {
                    return $logger;
                }
            }
        }

        if ($this->container->has(LoggerInterface::class)) {
            $logger = $this->container->get(LoggerInterface::class);
            if ($logger instanceof LoggerInterface) {
                return $logger;
            }
        }

        return null;
    }
}
