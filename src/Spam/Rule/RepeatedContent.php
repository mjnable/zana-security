<?php

declare(strict_types=1);

namespace Zana\Security\Spam\Rule;

use Closure;
use Psr\SimpleCache\CacheInterface;
use Zana\Security\Spam\RecordingSpamRuleInterface;
use Zana\Security\Spam\Signal;
use Zana\Security\Spam\Submission;

/**
 * The same text accepted on this form within the last minutes
 * (duplicate_minutes), from the same client, or with duplicate_scope
 * "everyone", from anyone. A fresh token does not make it new.
 *
 * Only a hash is kept, in the PSR-16 cache, never the text. Two identical
 * posts at the same instant can both pass: the rule catches repetition,
 * not a race.
 */
final readonly class RepeatedContent implements RecordingSpamRuleInterface
{
    private Closure $now;

    /**
     * @param 'client'|'everyone' $scope
     * @param (Closure(): int)|null $now
     * @param (Closure(\Throwable): void)|null $cacheFailed Told when the cache cannot be read or written (2.24.1)
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
            $this->failed($e);

            return null;
        }

        return is_int($until) && $until > ($this->now)()
            ? new Signal('repeated', 1, 'the same text was accepted ' . ($this->scope === 'everyone' ? '' : 'from this client ') . "within the last {$this->minutes} minute(s)")
            : null;
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
            $this->failed($e);
        }
    }

    private function failed(\Throwable $e): void
    {
        if ($this->cacheFailed !== null) {
            ($this->cacheFailed)($e);
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
