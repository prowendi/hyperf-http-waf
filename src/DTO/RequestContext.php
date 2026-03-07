<?php

declare(strict_types=1);

namespace Prowendi\HyperfHttpWaf\DTO;

final readonly class RequestContext
{
    /**
     * @param array<string, list<string>> $headers
     * @param array<string, mixed> $queryParams
     * @param array<string, mixed> $bodyParams
     * @param array<string, mixed> $cookies
     * @param list<TextInput> $queryInputs
     * @param list<TextInput> $bodyInputs
     * @param list<TextInput> $headerInputs
     * @param list<TextInput> $cookieInputs
     * @param list<UploadedFileMetadata> $files
     */
    public function __construct(
        public string $clientIp,
        public string $remoteAddr,
        public string $ipSource,
        public string $method,
        public string $path,
        public ?string $routeName,
        public array $headers,
        public array $queryParams,
        public array $bodyParams,
        public array $cookies,
        public array $queryInputs,
        public array $bodyInputs,
        public array $headerInputs,
        public array $cookieInputs,
        public array $files,
        public ?string $rawBody,
        public ?string $contentType,
        public int $bodySize,
        public bool $bodyTooLarge,
        public bool $bodyParseFailed,
        public int $queryParameterCount,
        public int $bodyParameterCount,
        public int $queryMaxDepth,
        public int $bodyMaxDepth,
        public int $queryMaxValueLength,
        public int $bodyMaxValueLength,
        public ?string $userAgent,
        public ?string $referer,
    ) {
    }
}
