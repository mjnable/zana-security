<?php

declare(strict_types=1);

namespace Zana\Security\Event;

/**
 * A password reset token was issued for a user (to be sent by email).
 */
final readonly class PasswordResetRequested implements SecurityEvent
{
    public function __construct(public string $userId)
    {
    }

    public function action(): string
    {
        return 'security.password_reset_requested';
    }
}
