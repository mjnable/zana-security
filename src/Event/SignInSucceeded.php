<?php

declare(strict_types=1);

namespace Zana\Security\Event;

/**
 * A user signed in with their password.
 */
final readonly class SignInSucceeded implements SecurityEvent
{
    public function __construct(
        public string $userId,
        public string $clientIp = '',
        public string $method = 'session',
    ) {
    }

    public function action(): string
    {
        return 'security.sign_in';
    }
}
