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
     */
    public function __construct(
        private CacheInterface $cache,
        private int $minutes,
        private string $scope = 'client',
        ?Closure $now = null,
    ) {
        $this->now = $now ?? time(...);
    }

    public function check(Submission $submission): ?Signal
    {
        $key = $this->key($submission);
        if ($key === null) {
            return null;
        }
        $until = $this->cache->get($key);

        return is_int($until) && $until > ($this->now)()
            ? new Signal('repeated', 1, 'the same text was accepted ' . ($this->scope === 'everyone' ? '' : 'from this client ') . "within the last {$this->minutes} minute(s)")
            : null;
    }

    public function accepted(Submission $submission): void
    {
        $key = $this->key($submission);
        if ($key !== null) {
            $this->cache->set($key, ($this->now)() + $this->minutes * 60, $this->minutes * 60);
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
