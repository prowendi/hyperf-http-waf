<?php

declare(strict_types=1);

namespace Prowendi\HyperfHttpWaf\Config;

use Prowendi\HyperfHttpWaf\Enum\WafMode;

final readonly class WafConfig
{
    private const ALL_TRUSTED_IP_HEADERS = [
        'x-forwarded-for',
        'x-real-ip',
        'forwarded',
    ];

    /**
     * @param array<string, mixed> $config
     */
    private function __construct(private array $config)
    {
    }

    /**
     * @param array<string, mixed> $config
     */
    public static function fromArray(array $config): self
    {
        return new self(self::merge(self::defaults(), $config));
    }

    public function all(): array
    {
        return $this->config;
    }

    public function enabled(): bool
    {
        return (bool) $this->get('enabled', true);
    }

    public function mode(): WafMode
    {
        return WafMode::fromString((string) $this->get('mode', 'observe'));
    }

    public function detectorEnabled(string $name): bool
    {
        return (bool) $this->get('detectors.' . $name, true);
    }

    public function trustedProxies(): array
    {
        return array_values(array_map('strval', (array) $this->get('trusted_proxies', [])));
    }

    public function trustsAllProxies(): bool
    {
        foreach ($this->trustedProxies() as $proxy) {
            if (trim($proxy) === '*') {
                return true;
            }
        }

        return false;
    }

    public function trustedHeaders(): array
    {
        $configured = array_values(array_map(
            static fn ($value): string => strtolower(trim((string) $value)),
            (array) $this->get('trusted_headers', [])
        ));

        if (! in_array('*', $configured, true)) {
            return array_values(array_filter($configured, static fn (string $value): bool => $value !== ''));
        }

        $headers = [];
        foreach ([...self::ALL_TRUSTED_IP_HEADERS, ...$configured] as $header) {
            if ($header === '' || $header === '*') {
                continue;
            }

            $headers[$header] = $header;
        }

        return array_values($headers);
    }

    public function allowedMethods(): array
    {
        return array_values(array_map(static fn ($value): string => strtoupper((string) $value), (array) $this->get('allowed_methods', [])));
    }

    public function bodySizeLimit(): int
    {
        return max(1024, (int) $this->get('body_size_limit', 262144));
    }

    public function scoreThreshold(): int
    {
        return max(1, (int) $this->get('decision.score_threshold', 70));
    }

    public function blockOnFirstMatch(): bool
    {
        return (bool) $this->get('decision.block_on_first_match', true);
    }

    public function maxParameterCount(string $scope): int
    {
        $default = 128;
        return max(1, (int) $this->get('thresholds.' . $scope . '_parameter_count', $default));
    }

    public function maxValueLength(): int
    {
        return max(256, (int) $this->get('thresholds.max_value_length', 4096));
    }

    public function maxNestedDepth(): int
    {
        return max(2, (int) $this->get('thresholds.max_nested_depth', 6));
    }

    public function maxScanLength(): int
    {
        return max(256, (int) $this->get('thresholds.max_scan_length', 4096));
    }

    public function maxHeaderValueLength(): int
    {
        return max(256, (int) $this->get('thresholds.header_value_length', 2048));
    }

    /**
     * @return list<string>
     */
    public function excludedHeaderNames(): array
    {
        return array_values(array_map(
            static fn ($value): string => strtolower(trim((string) $value)),
            (array) $this->get('header_detection.exclude_names', [])
        ));
    }

    public function whitelist(): array
    {
        return (array) $this->get('whitelist', []);
    }

    public function blacklist(): array
    {
        return (array) $this->get('blacklist', []);
    }

    public function sensitivePaths(): array
    {
        return array_values(array_map('strval', (array) $this->get('sensitive_paths', [])));
    }

    public function badUserAgents(): array
    {
        return array_values(array_map(static fn ($value): string => strtolower((string) $value), (array) $this->get('bad_user_agents', [])));
    }

    public function suspiciousFileExtensions(): array
    {
        return array_values(array_map(static fn ($value): string => strtolower((string) $value), (array) $this->get('files.suspicious_extensions', [])));
    }

    public function suspiciousMimeTypes(): array
    {
        return array_values(array_map(static fn ($value): string => strtolower((string) $value), (array) $this->get('files.suspicious_mime_types', [])));
    }

    public function maxFiles(): int
    {
        return max(1, (int) $this->get('files.max_files', 12));
    }

    public function maxFilenameLength(): int
    {
        return max(32, (int) $this->get('files.max_filename_length', 180));
    }

    public function maxTotalFileSize(): int
    {
        return max(1024, (int) $this->get('files.max_total_size', 10485760));
    }

    public function urlDecodePasses(): int
    {
        return max(0, (int) $this->get('normalizers.url_decode_passes', 2));
    }

    public function htmlEntityDecode(): bool
    {
        return (bool) $this->get('normalizers.html_entity_decode', true);
    }

    public function base64Probe(): bool
    {
        return (bool) $this->get('normalizers.base64_probe', true);
    }

    public function responseStatus(): int
    {
        return max(400, (int) $this->get('response.status', 403));
    }

    public function responseBody(): array
    {
        return (array) $this->get('response.body', ['code' => 403, 'message' => 'Request blocked by WAF.']);
    }

    public function responseHeaders(): array
    {
        $headers = [];
        foreach ((array) $this->get('response.headers', []) as $name => $value) {
            $headers[(string) $name] = (string) $value;
        }

        return $headers;
    }

    public function loggingEnabled(): bool
    {
        return (bool) $this->get('logging.enabled', true);
    }

    public function loggingChannel(): ?string
    {
        $channel = $this->get('logging.channel');
        if (! is_string($channel) || $channel === '') {
            return null;
        }

        return $channel;
    }

    public function logBodyMaxLength(): int
    {
        return max(256, (int) $this->get('logging.body_max_length', 2048));
    }

    public function uaMaxLength(): int
    {
        return max(64, (int) $this->get('logging.ua_max_length', 255));
    }

    public function matchedSampleLength(): int
    {
        return max(32, (int) $this->get('logging.matched_sample_length', 120));
    }

    public function rules(): array
    {
        return (array) $this->get('rules', []);
    }

    private function get(string $path, mixed $default = null): mixed
    {
        $segments = explode('.', $path);
        $value = $this->config;
        foreach ($segments as $segment) {
            if (! is_array($value) || ! array_key_exists($segment, $value)) {
                return $default;
            }

            $value = $value[$segment];
        }

        return $value;
    }

    private static function defaults(): array
    {
        static $defaults = null;

        if (is_array($defaults)) {
            return $defaults;
        }

        /** @var array<string, mixed> $loaded */
        $loaded = require dirname(__DIR__, 2) . '/publish/waf.php';

        return $defaults = $loaded;
    }

    private static function merge(array $defaults, array $override): array
    {
        foreach ($override as $key => $value) {
            if (! array_key_exists($key, $defaults)) {
                $defaults[$key] = $value;
                continue;
            }

            if (is_array($value) && is_array($defaults[$key]) && ! array_is_list($value) && ! array_is_list($defaults[$key])) {
                $defaults[$key] = self::merge($defaults[$key], $value);
                continue;
            }

            $defaults[$key] = $value;
        }

        return $defaults;
    }
}
