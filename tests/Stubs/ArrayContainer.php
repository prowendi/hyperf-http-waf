<?php

declare(strict_types=1);

namespace Prowendi\HyperfHttpWaf\Tests\Stubs;

use Psr\Container\ContainerExceptionInterface;
use Psr\Container\ContainerInterface;
use Psr\Container\NotFoundExceptionInterface;
use RuntimeException;

final class ArrayContainer implements ContainerInterface
{
    /**
     * @param array<string, mixed> $entries
     */
    public function __construct(private array $entries = [])
    {
    }

    public function get(string $id): mixed
    {
        if (! array_key_exists($id, $this->entries)) {
            throw new class('Service not found: ' . $id) extends RuntimeException implements NotFoundExceptionInterface {
            };
        }

        return $this->entries[$id];
    }

    public function has(string $id): bool
    {
        return array_key_exists($id, $this->entries);
    }

    public function set(string $id, mixed $value): void
    {
        $this->entries[$id] = $value;
    }
}
