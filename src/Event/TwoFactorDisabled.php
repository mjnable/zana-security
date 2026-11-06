<?php

declare(strict_types=1);

namespace Zana\Security\Event;

/**
 * A user's second factor was removed (2.16).
 */
final readonly class TwoFactorDisabled implements SecurityEvent
{
    public function __construct(public string $userId)
    {
    }

    public function action(): string
    {
        return 'security.two_factor_disabled';
    }
}
