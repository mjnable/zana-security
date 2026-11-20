<?php

declare(strict_types=1);

namespace Zana\Security\RateLimit;

use Closure;
use Psr\SimpleCache\CacheInterface;
use Zana\Cache\AtomicCacheInterface;

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
 * Keys are hashed, so client addresses are never stored.
 *
 * Counts are atomic with a cache that can count atomically (2.26, S34):
 * mj-zana/cache's AtomicCacheInterface, which every Zana store implements.
 * Each attempt increments first, and one beyond the limit takes its count
 * back, so attempts at the same instant take turns. With another PSR-16
 * cache, the count is read and then written: attempts that read before any
 * writes all pass (twenty at once passed a limit of five), and `check` warns
 * (security.atomic_cache).
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
        return $this->count_($key, $max, $window, $strategy, true);
    }

    /**
     * Whether an attempt would be allowed, without counting one (2.19.1).
     *
     * @param 'fixed'|'sliding' $strategy
     */
    public function peek(string $key, int $max, int $window, string $strategy = 'fixed'): RateLimitResult
    {
        return $this->count_($key, $max, $window, $strategy, false);
    }

    /**
     * @param 'fixed'|'sliding' $strategy
     */
    private function count_(string $key, int $max, int $window, string $strategy, bool $record): RateLimitResult
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

        $carried = 0;
        if ($strategy === 'sliding') {
            $previous = $this->count(self::PREFIX . $hash . '.' . ($current - 1));
            $carried = (int) floor($previous * ($window - $elapsed) / $window);
        }

        if ($record && $this->cache instanceof AtomicCacheInterface) {
            // Count first, then decide: attempts at the same instant each get their own number (2.26, S34).
            $count = $this->cache->increment($currentKey, 1, $window * 2) - 1;
            if ($count + $carried >= $max) {
                $this->cache->increment($currentKey, -1, $window * 2);   // a refused attempt is not counted, as before

                return new RateLimitResult(false, $max, 0, $resetAfter);
            }

            return new RateLimitResult(true, $max, max(0, $max - $count - $carried - 1), $resetAfter);
        }

        $count = $this->count($currentKey);
        $weighted = $count + $carried;

        if ($weighted >= $max) {
            return new RateLimitResult(false, $max, 0, $resetAfter);
        }

        if (!$record) {
            return new RateLimitResult(true, $max, max(0, $max - $weighted), $resetAfter);
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
