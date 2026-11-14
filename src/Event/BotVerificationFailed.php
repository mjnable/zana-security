<?php

declare(strict_types=1);

namespace Zana\Security\Event;

/**
 * A request refused because its CAPTCHA token did not prove a person
 * (2.25, FE-64). It holds why, never the token.
 */
final readonly class BotVerificationFailed implements SecurityEvent
{
    /**
     * @param list<string> $reasons Such as "missing-token", "low-score" or the provider's codes, e.g. "timeout-or-duplicate"
     */
    public function __construct(
        public string $path,
        public ?string $action,
        public array $reasons,
        public ?float $score = null,
        public string $clientIp = '',
    ) {
    }

    public function action(): string
    {
        return 'security.bot_verification_failed';
    }
}
