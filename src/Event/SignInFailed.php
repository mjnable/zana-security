<?php

declare(strict_types=1);

namespace Zana\Security\Event;

/**
 * A sign-in was refused: a wrong login or password ("invalid_credentials"),
 * or too many attempts ("throttled"). $login is what was typed, which may
 * not be an account; the password is never part of the event.
 */
final readonly class SignInFailed implements SecurityEvent
{
    public const string INVALID_CREDENTIALS = 'invalid_credentials';

    public const string THROTTLED = 'throttled';

    public function __construct(
        public string $login,
        public string $reason = self::INVALID_CREDENTIALS,
        public string $clientIp = '',
    ) {
    }

    public function action(): string
    {
        return 'security.sign_in_failed';
    }
}
