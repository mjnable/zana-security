<?php

declare(strict_types=1);

namespace Zana\Security\Event;

/**
 * A valid password reset token was used up, so the user is about to set a
 * new password.
 */
final readonly class PasswordResetTokenUsed implements SecurityEvent
{
    public function __construct(public string $userId)
    {
    }

    public function action(): string
    {
        return 'security.password_reset';
    }
}
