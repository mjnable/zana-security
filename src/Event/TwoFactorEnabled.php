<?php

declare(strict_types=1);

namespace Zana\Security\Event;

/**
 * A user confirmed a new second factor (2.16).
 */
final readonly class TwoFactorEnabled implements SecurityEvent
{
    public function __construct(public string $userId)
    {
    }

    public function action(): string
    {
        return 'security.two_factor_enabled';
    }
}
