<?php

declare(strict_types=1);

namespace Prowendi\HyperfHttpWaf\Support;

use Prowendi\HyperfHttpWaf\Config\WafConfig;
use Prowendi\HyperfHttpWaf\Result\DetectionResult;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;
use RuntimeException;

final class BlockingResponseFactory
{
    public function __construct(
        private readonly ?ResponseFactoryInterface $responseFactory = null,
        private readonly ?StreamFactoryInterface $streamFactory = null,
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

        $response = $this->createBaseResponse($config->responseStatus());
        foreach ($config->responseHeaders() as $name => $value) {
            $response = $response->withHeader($name, $value);
        }

        if ($this->streamFactory !== null) {
            return $response->withBody($this->streamFactory->createStream($encoded));
        }

        if (class_exists(\Hyperf\HttpMessage\Stream\SwooleStream::class)) {
            return $response->withBody(new \Hyperf\HttpMessage\Stream\SwooleStream($encoded));
        }

        throw new RuntimeException('Unable to create WAF blocking response body stream.');
    }

    private function createBaseResponse(int $status): ResponseInterface
    {
        if ($this->responseFactory !== null) {
            return $this->responseFactory->createResponse($status);
        }

        if (class_exists(\Hyperf\HttpMessage\Server\Response::class)) {
            return (new \Hyperf\HttpMessage\Server\Response())->withStatus($status);
        }

        throw new RuntimeException('Unable to create WAF blocking response. No response factory available.');
    }
}
