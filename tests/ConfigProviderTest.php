<?php

declare(strict_types=1);

namespace Prowendi\HyperfHttpWaf\Tests;

use Prowendi\HyperfHttpWaf\Config\WafConfig;
use Prowendi\HyperfHttpWaf\ConfigProvider;

final class ConfigProviderTest extends TestCase
{
    public function testConfigProviderCanBeLoaded(): void
    {
        $provider = new ConfigProvider();
        $config = $provider();

        self::assertArrayHasKey('waf', $config);
        self::assertArrayHasKey('publish', $config);
        self::assertSame('observe', $config['waf']['mode']);
        self::assertTrue($config['waf']['enabled']);
    }

    public function testDefaultConfigCanBeRead(): void
    {
        $config = WafConfig::fromArray([
            'mode' => 'block',
            'decision' => [
                'score_threshold' => 60,
            ],
        ]);

        self::assertSame('block', $config->mode()->value);
        self::assertSame(60, $config->scoreThreshold());
        self::assertSame(262144, $config->bodySizeLimit());
        self::assertContains('GET', $config->allowedMethods());
    }
}
