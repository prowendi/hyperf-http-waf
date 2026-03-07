<?php

declare(strict_types=1);

namespace Prowendi\HyperfHttpWaf\Support;

use Prowendi\HyperfHttpWaf\Config\WafConfig;
use Hyperf\Contract\ConfigInterface;
use Psr\Container\ContainerInterface;

final class WafConfigFactory
{
    private ?WafConfig $cached = null;

    public function __construct(private readonly ContainerInterface $container)
    {
    }

    public function create(): WafConfig
    {
        if ($this->cached !== null) {
            return $this->cached;
        }

        $config = [];

        if ($this->container->has(ConfigInterface::class)) {
            $service = $this->container->get(ConfigInterface::class);
            if ($service instanceof ConfigInterface) {
                $payload = $service->get('waf', []);
                $config = is_array($payload) ? $payload : [];
            }
        } elseif ($this->container->has('config')) {
            $service = $this->container->get('config');
            if (is_array($service)) {
                $payload = $service['waf'] ?? [];
                $config = is_array($payload) ? $payload : [];
            }
        }

        return $this->cached = WafConfig::fromArray($config);
    }

    public function reset(): void
    {
        $this->cached = null;
    }
}
