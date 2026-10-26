<?php

declare(strict_types=1);

namespace Zana\Security\RateLimit;

use Closure;
use Psr\SimpleCache\CacheInterface;

/**
 * Counts attempts per key in a PSR-16 cache (FE-10):
 *
 *     $result = $limiter->attempt('contact:' . $ip, max: 5, window: 3600);
 *
 * - "fixed" counts per window (e.g. per clock hour): cheap, but allows a burst
 *   at the edge of two windows.
 * - "sliding" weighs the previous window by how much of it still overlaps the
 *   last $window seconds, which smooths that burst.
 *
 * Keys are hashed, so client addresses are never stored. Counts are not
 * atomic: under heavy concurrency a few extra attempts may pass.
 */
final readonly class RateLimiter
{
    private const string PREFIX = 'zana.rate.';

    /** @var Closure(): int */
    private Closure $now;

    /**
     * @param (Closure(): int)|null $clock
     */
    public function __construct(private CacheInterface $cache, ?Closure $clock = null)
    {
        $this->now = $clock ?? static fn (): int => time();
    }

    /**
     * Count one attempt, unless the limit is already reached.
     *
     * @param 'fixed'|'sliding' $strategy
     */
    public function attempt(string $key, int $max, int $window, string $strategy = 'fixed'): RateLimitResult
    {
        if ($max < 1 || $window < 1) {
            throw new \InvalidArgumentException('A rate limit needs max >= 1 and window >= 1.');
        }

        $now = ($this->now)();
        $current = intdiv($now, $window);
        $elapsed = $now - $current * $window;
        $resetAfter = $window - $elapsed;
        $hash = hash('xxh128', $key);
        $currentKey = self::PREFIX . $hash . '.' . $current;

        $count = $this->count($currentKey);
        $weighted = $count;
        if ($strategy === 'sliding') {
            $previous = $this->count(self::PREFIX . $hash . '.' . ($current - 1));
            $weighted = $count + (int) floor($previous * ($window - $elapsed) / $window);
        }

        if ($weighted >= $max) {
            return new RateLimitResult(false, $max, 0, $resetAfter);
        }

        $this->cache->set($currentKey, $count + 1, $window * 2);

        return new RateLimitResult(true, $max, max(0, $max - $weighted - 1), $resetAfter);
    }

    /**
     * Forget the attempts of a key, e.g. after a successful login.
     */
    public function reset(string $key, int $window): void
    {
        $current = intdiv(($this->now)(), $window);
        $hash = hash('xxh128', $key);
        $this->cache->deleteMultiple([self::PREFIX . $hash . '.' . $current, self::PREFIX . $hash . '.' . ($current - 1)]);
    }

    private function count(string $key): int
    {
        $count = $this->cache->get($key, 0);

        return is_int($count) ? $count : 0;
    }
}
