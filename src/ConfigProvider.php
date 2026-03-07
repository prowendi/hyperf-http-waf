<?php

declare(strict_types=1);

namespace Prowendi\HyperfHttpWaf;

use Prowendi\HyperfHttpWaf\Contract\ReporterInterface;
use Prowendi\HyperfHttpWaf\Contract\RuleProviderInterface;
use Prowendi\HyperfHttpWaf\Logger\LoggerReporter;
use Prowendi\HyperfHttpWaf\Middleware\WafMiddleware;
use Prowendi\HyperfHttpWaf\Support\ConfigRuleProvider;
use Prowendi\HyperfHttpWaf\Support\WafMiddlewareFactory;

final class ConfigProvider
{
    public function __invoke(): array
    {
        $destination = 'config/autoload/waf.php';
        if (defined('BASE_PATH')) {
            $destination = BASE_PATH . '/config/autoload/waf.php';
        }

        return [
            'dependencies' => [
                ReporterInterface::class => LoggerReporter::class,
                RuleProviderInterface::class => ConfigRuleProvider::class,
                WafMiddleware::class => WafMiddlewareFactory::class,
            ],
            'waf' => require __DIR__ . '/../publish/waf.php',
            'publish' => [
                [
                    'id' => 'waf-config',
                    'description' => 'Default configuration for prowendi/hyperf-http-waf.',
                    'source' => __DIR__ . '/../publish/waf.php',
                    'destination' => $destination,
                ],
            ],
        ];
    }
}
