<?php

declare(strict_types=1);

namespace Zana\Security\TwoFactor;

use Closure;
use Psr\SimpleCache\CacheInterface;
use Zana\Http\Exception\TooManyRequestsHttpException;
use Zana\Security\Internal\SecretBox;
use Zana\Security\RateLimit\RateLimiter;

/**
 * Numeric codes sent to confirm a phone number or an email address (FE-56):
 *
 *     $code = $codes->issue('+243810000000', 'phone.confirm');   // send it by SMS or WhatsApp
 *     $codes->verify('+243810000000', 'phone.confirm', $typed);  // true once
 *
 * - A code is stored as an HMAC in the cache, expires (default 10 minutes),
 *   and works once; issuing a new one replaces the old one.
 * - It is refused after max attempts (default 5) wrong tries.
 * - Issuing is rate-limited per subject and purpose (security.one_time_codes.max_issues
 *   per security.one_time_codes.window seconds).
 *
 * Delivery is the application's (an SMS or WhatsApp provider).
 */
final readonly class OneTimeCodes
{
    /** @var Closure(): int */
    private Closure $clock;

    private SecretBox $box;

    /**
     * @param string $key Keys the codes' HMACs: at least 32 characters
     * @param (Closure(): int)|null $clock
     */
    public function __construct(
        private CacheInterface $cache,
        #[\SensitiveParameter] string $key,
        private ?RateLimiter $limiter = null,
        private int $maxIssues = 5,
        private int $window = 3600,
        ?Closure $clock = null,
    ) {
        $this->box = new SecretBox($key);
        $this->clock = $clock ?? time(...);
    }

    /**
     * @param string $subject Who or what the code confirms, e.g. a phone number
     * @param string $purpose What it is for, e.g. "phone.confirm"
     *
     * @throws TooManyRequestsHttpException After too many codes for this subject and purpose
     */
    public function issue(string $subject, string $purpose, int $digits = 6, int $ttl = 600, int $maxAttempts = 5): string
    {
        $key = $this->key($subject, $purpose);
        $limit = $this->limiter?->attempt("otc:{$key}", $this->maxIssues, $this->window);
        if ($limit !== null && !$limit->allowed) {
            throw new TooManyRequestsHttpException($limit->resetAfter, 'Too many codes were sent. Please wait and try again.');
        }

        $code = str_pad((string) random_int(0, 10 ** $digits - 1), $digits, '0', STR_PAD_LEFT);
        $this->cache->set($key, ['h' => $this->box->mac("{$key}|{$code}"), 'e' => ($this->clock)() + $ttl, 'a' => $maxAttempts], $ttl);

        return $code;
    }

    /**
     * True once for the right code within its time; false when it is wrong, expired, used, or out of attempts.
     */
    public function verify(string $subject, string $purpose, string $code): bool
    {
        $key = $this->key($subject, $purpose);
        $entry = $this->cache->get($key);
        if (!is_array($entry) || !is_string($entry['h'] ?? null) || !is_int($entry['e'] ?? null) || !is_int($entry['a'] ?? null)) {
            return false;
        }
        $left = $entry['e'] - ($this->clock)();
        if ($left <= 0 || $entry['a'] <= 0) {
            $this->cache->delete($key);

            return false;
        }

        if (hash_equals($entry['h'], $this->box->mac("{$key}|" . trim($code)))) {
            $this->cache->delete($key);

            return true;
        }
        $entry['a']--;
        $entry['a'] > 0 ? $this->cache->set($key, $entry, $left) : $this->cache->delete($key);

        return false;
    }

    private function key(string $subject, string $purpose): string
    {
        return 'zana.otc.' . hash('xxh128', $purpose . "\n" . $subject);
    }
}
