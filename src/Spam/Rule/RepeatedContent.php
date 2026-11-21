<?php

declare(strict_types=1);

namespace Zana\Security\Spam\Rule;

use Closure;
use Psr\SimpleCache\CacheInterface;
use Zana\Cache\AtomicCacheInterface;
use Zana\Security\Spam\ClaimingSpamRuleInterface;
use Zana\Security\Spam\Signal;
use Zana\Security\Spam\Submission;

/**
 * The same text accepted on this form within the last minutes
 * (duplicate_minutes), from the same client, or with duplicate_scope
 * "everyone", from anyone. A fresh token does not make it new.
 *
 * Only a hash is kept, in the PSR-16 cache, never the text. Since 2.25 the
 * hash is reserved as soon as the rules let a post through, and released if
 * the handler fails, so the same text sent while the first is still being
 * handled is caught. Since 2.29 it is claimed in one step on a Zana cache, so
 * two posts at the same instant cannot both pass either; on another PSR-16
 * cache they still can, and `check` warns (security.atomic_cache).
 */
final readonly class RepeatedContent implements ClaimingSpamRuleInterface
{
    private Closure $now;

    /**
     * @param 'client'|'everyone' $scope
     * @param (Closure(): int)|null $now
     * @param (Closure(\Throwable, 'read'|'write'|'delete'): void)|null $cacheFailed Told when the cache cannot be read or written (2.24.1)
     */
    public function __construct(
        private CacheInterface $cache,
        private int $minutes,
        private string $scope = 'client',
        ?Closure $now = null,
        private ?Closure $cacheFailed = null,
    ) {
        $this->now = $now ?? time(...);
    }

    /**
     * When the cache cannot be read, the rule finds nothing for this post
     * (2.24.1): the other rules still apply, and a real message is not
     * refused because a cache server is down.
     */
    public function check(Submission $submission): ?Signal
    {
        $key = $this->key($submission);
        if ($key === null) {
            return null;
        }
        try {
            $until = $this->cache->get($key);
        } catch (\Throwable $e) {
            $this->failed($e, 'read');

            return null;
        }

        return is_int($until) && $until > ($this->now)() ? $this->signal() : null;
    }

    private function signal(): Signal
    {
        return new Signal('repeated', 1, 'the same text was accepted ' . ($this->scope === 'everyone' ? '' : 'from this client ') . "within the last {$this->minutes} minute(s)");
    }

    /**
     * Called after the handler took the message: a cache that cannot be
     * written is reported, never thrown, so the visitor is not told that a
     * message which was received has failed (2.24.1).
     */
    public function accepted(Submission $submission): void
    {
        $key = $this->key($submission);
        if ($key === null) {
            return;
        }
        try {
            $this->cache->set($key, ($this->now)() + $this->minutes * 60, $this->minutes * 60);
        } catch (\Throwable $e) {
            $this->failed($e, 'write');
        }
    }

    /**
     * Holds the hash while the handler runs (2.25), for as long as an
     * accepted one, in case the request ends without a word back.
     */
    public function reserve(Submission $submission): void
    {
        $this->accepted($submission);
    }

    /**
     * Holds the hash in one step (2.29): on a cache that adds atomically
     * (mj-zana/cache's AtomicCacheInterface), only the first of two identical
     * posts at the same instant gets it, and the other gets the signal. On
     * another cache, it reserves as before and finds nothing. A cache that
     * cannot be written finds nothing either: a real message is not refused
     * because the cache is down.
     */
    public function claim(Submission $submission): ?Signal
    {
        $key = $this->key($submission);
        if ($key === null) {
            return null;
        }
        if (!$this->cache instanceof AtomicCacheInterface) {
            $this->reserve($submission);

            return null;
        }
        try {
            $claimed = $this->cache->add($key, ($this->now)() + $this->minutes * 60, $this->minutes * 60);
        } catch (\Throwable $e) {
            $this->failed($e, 'write');

            return null;
        }

        return $claimed ? null : $this->signal();
    }

    /**
     * The handler answered with an error or failed: the text was not
     * accepted, so sending it again is not a repeat (2.25).
     */
    public function release(Submission $submission): void
    {
        $key = $this->key($submission);
        if ($key === null) {
            return;
        }
        try {
            $this->cache->delete($key);
        } catch (\Throwable $e) {
            $this->failed($e, 'delete');
        }
    }

    /**
     * @param 'read'|'write'|'delete' $operation
     */
    private function failed(\Throwable $e, string $operation): void
    {
        if ($this->cacheFailed !== null) {
            ($this->cacheFailed)($e, $operation);
        }
    }

    private function key(Submission $submission): ?string
    {
        $text = $submission->normalized();
        if ($text === '') {
            return null;   // an empty form is not a message
        }
        $who = $this->scope === 'everyone' ? 'everyone' : $submission->client;

        return 'zana_spam_' . hash('sha256', $submission->form . "\0" . $who . "\0" . $text);
    }
}
