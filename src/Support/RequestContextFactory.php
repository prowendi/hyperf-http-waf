<?php

declare(strict_types=1);

namespace Prowendi\HyperfHttpWaf\Support;

use Prowendi\HyperfHttpWaf\Config\WafConfig;
use Prowendi\HyperfHttpWaf\DTO\RequestContext;
use Prowendi\HyperfHttpWaf\DTO\TextInput;
use Prowendi\HyperfHttpWaf\DTO\UploadedFileMetadata;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\UploadedFileInterface;
use Throwable;

final class RequestContextFactory
{
    public function __construct(
        private readonly RealIpResolver $realIpResolver = new RealIpResolver(),
        private readonly InputFlattener $inputFlattener = new InputFlattener(),
    ) {
    }

    public function create(ServerRequestInterface $request, WafConfig $config): RequestContext
    {
        $resolvedIp = $this->realIpResolver->resolve($request, $config);
        $headers = $this->normalizeHeaders($request->getHeaders());
        $queryParams = $this->normalizeAssociativePayload($request->getQueryParams());
        $cookies = $this->normalizeAssociativePayload($request->getCookieParams());

        $queryPayload = $this->inputFlattener->flatten($queryParams, 'query', $config->maxNestedDepth());
        $cookiePayload = $this->inputFlattener->flatten($cookies, 'cookie', $config->maxNestedDepth());
        $headerInputs = $this->flattenHeaders($headers, $config);

        $bodyInfo = $this->extractBody($request, $config);
        $files = $this->flattenUploadedFiles($request->getUploadedFiles(), $config->contentInspection());

        return new RequestContext(
            clientIp: $resolvedIp->clientIp,
            remoteAddr: $resolvedIp->remoteAddr,
            ipSource: $resolvedIp->source,
            method: strtoupper($request->getMethod()),
            path: $request->getUri()->getPath() === '' ? '/' : $request->getUri()->getPath(),
            routeName: $this->resolveRouteName($request),
            headers: $headers,
            queryParams: $queryParams,
            bodyParams: $bodyInfo['body_params'],
            cookies: $cookies,
            queryInputs: $queryPayload->inputs,
            bodyInputs: $bodyInfo['inputs'],
            headerInputs: $headerInputs,
            cookieInputs: $cookiePayload->inputs,
            files: $files,
            rawBody: $bodyInfo['raw_body'],
            contentType: $bodyInfo['content_type'],
            bodySize: $bodyInfo['body_size'],
            bodyTooLarge: $bodyInfo['body_too_large'],
            bodyParseFailed: $bodyInfo['body_parse_failed'],
            queryParameterCount: $queryPayload->count,
            bodyParameterCount: $bodyInfo['body_parameter_count'],
            queryMaxDepth: $queryPayload->maxDepth,
            bodyMaxDepth: $bodyInfo['body_max_depth'],
            queryMaxValueLength: $queryPayload->maxValueLength,
            bodyMaxValueLength: $bodyInfo['body_max_value_length'],
            userAgent: $request->getHeaderLine('user-agent') !== '' ? $request->getHeaderLine('user-agent') : null,
            referer: $request->getHeaderLine('referer') !== '' ? $request->getHeaderLine('referer') : null,
        );
    }

    /**
     * @param array<string, string|string[]> $headers
     * @return array<string, list<string>>
     */
    private function normalizeHeaders(array $headers): array
    {
        $normalized = [];
        foreach ($headers as $name => $values) {
            $normalized[strtolower((string) $name)] = array_values(array_map('strval', (array) $values));
        }

        return $normalized;
    }

    private function normalizeAssociativePayload(array $payload): array
    {
        $normalized = [];
        foreach ($payload as $key => $value) {
            $normalized[(string) $key] = $value;
        }

        return $normalized;
    }

    /**
     * @param array<string, list<string>> $headers
     * @return list<TextInput>
     */
    private function flattenHeaders(array $headers, WafConfig $config): array
    {
        $inputs = [];
        $excluded = $config->excludedHeaderNames();
        foreach ($headers as $name => $values) {
            if ($name === 'cookie' || $this->shouldSkipHeader($name, $excluded)) {
                continue;
            }

            foreach ($values as $index => $value) {
                $label = count($values) > 1 ? $name . '[' . $index . ']' : $name;
                $inputs[] = new TextInput('header', $label, $value);
            }
        }

        return $inputs;
    }

    /**
     * @param list<string> $excluded
     */
    private function shouldSkipHeader(string $name, array $excluded): bool
    {
        $normalized = strtolower($name);
        foreach ($excluded as $pattern) {
            if ($pattern === '') {
                continue;
            }

            if (str_contains($pattern, '*')) {
                if (fnmatch($pattern, $normalized)) {
                    return true;
                }

                continue;
            }

            if ($normalized === $pattern) {
                return true;
            }
        }

        return false;
    }

    /**
     * @return array{
     *     body_params: array<string, mixed>,
     *     inputs: list<TextInput>,
     *     raw_body: ?string,
     *     content_type: ?string,
     *     body_size: int,
     *     body_too_large: bool,
     *     body_parse_failed: bool,
     *     body_parameter_count: int,
     *     body_max_depth: int,
     *     body_max_value_length: int
     * }
     */
    private function extractBody(ServerRequestInterface $request, WafConfig $config): array
    {
        $contentTypeHeader = strtolower(trim(explode(';', $request->getHeaderLine('content-type'))[0] ?? ''));
        $bodyPreview = $this->readBodyPreview($request, $config->bodySizeLimit());

        $bodyParams = [];
        $bodyInputs = [];
        $bodyParseFailed = false;
        $bodyParameterCount = 0;
        $bodyMaxDepth = 0;
        $bodyMaxValueLength = 0;
        $rawBody = $bodyPreview['preview'];

        if (! $bodyPreview['too_large']) {
            $parsedBody = $request->getParsedBody();
            if (is_array($parsedBody)) {
                $bodyParams = $this->normalizeAssociativePayload($parsedBody);
                $flattened = $this->inputFlattener->flatten($bodyParams, 'body', $config->maxNestedDepth());
                $bodyInputs = $flattened->inputs;
                $bodyParameterCount = $flattened->count;
                $bodyMaxDepth = $flattened->maxDepth;
                $bodyMaxValueLength = $flattened->maxValueLength;
            } elseif (is_scalar($parsedBody)) {
                $flattened = $this->inputFlattener->flatten(['body' => (string) $parsedBody], 'body', $config->maxNestedDepth());
                $bodyInputs = $flattened->inputs;
                $bodyParameterCount = $flattened->count;
                $bodyMaxDepth = $flattened->maxDepth;
                $bodyMaxValueLength = $flattened->maxValueLength;
            } elseif ($rawBody !== null && $rawBody !== '' && $contentTypeHeader !== '') {
                if ($contentTypeHeader === 'application/json') {
                    $decoded = json_decode($rawBody, true);
                    if (json_last_error() === JSON_ERROR_NONE && is_array($decoded)) {
                        $bodyParams = $this->normalizeAssociativePayload($decoded);
                        $flattened = $this->inputFlattener->flatten($bodyParams, 'body', $config->maxNestedDepth());
                        $bodyInputs = $flattened->inputs;
                        $bodyParameterCount = $flattened->count;
                        $bodyMaxDepth = $flattened->maxDepth;
                        $bodyMaxValueLength = $flattened->maxValueLength;
                    } else {
                        $bodyParseFailed = true;
                        $bodyInputs = [new TextInput('body', 'raw', $rawBody)];
                        $bodyParameterCount = 1;
                        $bodyMaxDepth = 1;
                        $bodyMaxValueLength = strlen($rawBody);
                    }
                } elseif ($contentTypeHeader === 'application/x-www-form-urlencoded') {
                    parse_str($rawBody, $decoded);
                    if (is_array($decoded)) {
                        $bodyParams = $this->normalizeAssociativePayload($decoded);
                        $flattened = $this->inputFlattener->flatten($bodyParams, 'body', $config->maxNestedDepth());
                        $bodyInputs = $flattened->inputs;
                        $bodyParameterCount = $flattened->count;
                        $bodyMaxDepth = $flattened->maxDepth;
                        $bodyMaxValueLength = $flattened->maxValueLength;
                    }
                } elseif ($contentTypeHeader !== 'multipart/form-data' && $this->isTextualContentType($contentTypeHeader)) {
                    $bodyInputs = [new TextInput('body', 'raw', $rawBody)];
                    $bodyParameterCount = 1;
                    $bodyMaxDepth = 1;
                    $bodyMaxValueLength = strlen($rawBody);
                }
            }

            // Fallback: a body that the framework did not parse (missing or
            // non-standard content type) is still attacker-controlled input
            // and must be scanned as raw data.
            if ($bodyInputs === []
                && (is_string($rawBody) && $rawBody !== '')
                && ! ($contentTypeHeader === 'multipart/form-data' && $request->getUploadedFiles() !== [])
            ) {
                $bodyInputs = [new TextInput('body', 'raw', $rawBody)];
                $bodyParameterCount = 1;
                $bodyMaxDepth = 1;
                $bodyMaxValueLength = strlen($rawBody);
            }
        }

        return [
            'body_params' => $bodyParams,
            'inputs' => $bodyInputs,
            'raw_body' => $rawBody,
            'content_type' => $contentTypeHeader !== '' ? $contentTypeHeader : null,
            'body_size' => $bodyPreview['size'],
            'body_too_large' => $bodyPreview['too_large'],
            'body_parse_failed' => $bodyParseFailed,
            'body_parameter_count' => $bodyParameterCount,
            'body_max_depth' => $bodyMaxDepth,
            'body_max_value_length' => $bodyMaxValueLength,
        ];
    }

    /**
     * @return array{preview: ?string, size: int, too_large: bool}
     */
    private function readBodyPreview(ServerRequestInterface $request, int $limit): array
    {
        $stream = $request->getBody();
        $size = (int) ($stream->getSize() ?? 0);
        if ($size > $limit && $size > 0) {
            return [
                'preview' => null,
                'size' => $size,
                'too_large' => true,
            ];
        }

        if (! $stream->isSeekable()) {
            return [
                'preview' => null,
                'size' => $size,
                'too_large' => false,
            ];
        }

        try {
            $position = $stream->tell();
            $stream->rewind();
            $preview = $stream->read($limit + 1);
            $stream->seek($position);
        } catch (Throwable) {
            // Best effort to leave the stream where it was found so the
            // business handler does not read misaligned body data.
            try {
                if (isset($position) && $stream->isSeekable()) {
                    $stream->seek($position);
                }
            } catch (Throwable) {
                // intentionally ignored
            }

            return [
                'preview' => null,
                'size' => $size,
                'too_large' => false,
            ];
        }

        $tooLarge = strlen($preview) > $limit;
        if ($tooLarge) {
            $preview = substr($preview, 0, $limit);
        }

        if ($size === 0) {
            $size = strlen($preview);
        }

        return [
            'preview' => $preview !== '' ? $preview : null,
            'size' => $size,
            'too_large' => $tooLarge,
        ];
    }

    /**
     * @param array<string, UploadedFileInterface|array<array-key, UploadedFileInterface|mixed>> $files
     * @return list<UploadedFileMetadata>
     */
    private function flattenUploadedFiles(array $files, bool $readContent): array
    {
        $metadata = [];
        foreach ($files as $field => $file) {
            $this->walkUploadedFiles((string) $field, $file, $metadata, $readContent);
        }

        return $metadata;
    }

    /**
     * @param array<int, UploadedFileMetadata> $metadata
     */
    private function walkUploadedFiles(string $field, mixed $file, array &$metadata, bool $readContent): void
    {
        if ($file instanceof UploadedFileInterface) {
            $metadata[] = UploadedFileMetadata::fromUploadedFile($field, $file, $readContent);
            return;
        }

        if (! is_array($file)) {
            return;
        }

        foreach ($file as $key => $nested) {
            $this->walkUploadedFiles($field . '[' . $key . ']', $nested, $metadata, $readContent);
        }
    }

    private function resolveRouteName(ServerRequestInterface $request): ?string
    {
        foreach (['route_name', 'route', 'handler', 'matched_route'] as $key) {
            $attribute = $request->getAttribute($key);
            if (is_string($attribute) && $attribute !== '') {
                return $attribute;
            }

            if (is_object($attribute) && method_exists($attribute, 'getName')) {
                $name = $attribute->getName();
                if (is_string($name) && $name !== '') {
                    return $name;
                }
            }

            if (is_array($attribute) && isset($attribute['name']) && is_string($attribute['name']) && $attribute['name'] !== '') {
                return $attribute['name'];
            }
        }

        return null;
    }

    private function isTextualContentType(string $contentType): bool
    {
        return str_starts_with($contentType, 'text/')
            || str_contains($contentType, 'json')
            || str_contains($contentType, 'xml')
            || str_contains($contentType, 'javascript');
    }
}
