<?php

declare(strict_types=1);

namespace Zana\Security\Event;

/**
 * A form post refused by its spam rules (2.24, FE-63). It names the rules
 * that found something, never the text, so a person can see what was refused
 * and why, and loosen a rule that refuses real messages. Zana's rules come
 * with their reasons (counts, the configured term); an application's rule by
 * its name and points only, as its reason may hold the text (2.24.1).
 */
final readonly class SpamRefused implements SecurityEvent
{
    /**
     * @param list<string> $reasons Each rule that found something, as "rule: reason"
     */
    public function __construct(
        public string $form,
        public array $reasons,
        public int $points,
        public string $clientIp = '',
    ) {
    }

    public function action(): string
    {
        return 'security.spam_refused';
    }
}
