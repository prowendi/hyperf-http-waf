<?php

declare(strict_types=1);

namespace Prowendi\HyperfHttpWaf\Support;

use Prowendi\HyperfHttpWaf\Config\WafConfig;
use Prowendi\HyperfHttpWaf\Result\DetectionResult;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamFactoryInterface;

final class BlockingResponseFactory
{
    public function __construct(
        private readonly ResponseFactoryInterface $responseFactory,
        private readonly StreamFactoryInterface $streamFactory,
    ) {
    }

    public function create(DetectionResult $result, WafConfig $config): ResponseInterface
    {
        $payload = $config->responseBody();
        $payload['action'] = $result->action->value;

        $encoded = json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        if (! is_string($encoded)) {
            $encoded = '{"code":403,"message":"Request blocked by WAF."}';
        }

        $response = $this->responseFactory->createResponse($config->responseStatus());
        foreach ($config->responseHeaders() as $name => $value) {
            $response = $response->withHeader($name, $value);
        }

        return $response->withBody($this->streamFactory->createStream($encoded));
    }
}
