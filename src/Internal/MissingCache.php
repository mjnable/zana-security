<?php

declare(strict_types=1);

namespace Zana\Security\Internal;

use Psr\SimpleCache\CacheInterface;
use Zana\Security\SecurityException;

/**
 * Stands in for the PSR-16 cache when the application has none, so the
 * services that need one (rate limiting, password reset tokens) can be
 * created, and check and doctor pass, and fail only when they are used.
 *
 * @internal
 */
final readonly class MissingCache implements CacheInterface
{
    public function __construct(private string $feature)
    {
    }

    public function get(string $key, mixed $default = null): mixed
    {
        throw $this->missing();
    }

    public function set(string $key, mixed $value, \DateInterval|int|null $ttl = null): bool
    {
        throw $this->missing();
    }

    public function delete(string $key): bool
    {
        throw $this->missing();
    }

    public function clear(): bool
    {
        throw $this->missing();
    }

    public function getMultiple(iterable $keys, mixed $default = null): iterable
    {
        throw $this->missing();
    }

    /**
     * @param iterable<mixed> $values
     */
    public function setMultiple(iterable $values, \DateInterval|int|null $ttl = null): bool
    {
        throw $this->missing();
    }

    public function deleteMultiple(iterable $keys): bool
    {
        throw $this->missing();
    }

    public function has(string $key): bool
    {
        throw $this->missing();
    }

    private function missing(): SecurityException
    {
        return new SecurityException("{$this->feature} need a PSR-16 cache: register mj-zana/cache or another " . CacheInterface::class . '.');
    }
}
