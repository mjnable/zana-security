<?php

declare(strict_types=1);

namespace Zana\Security\Event;

/**
 * A signed-in user signed out.
 */
final readonly class SignedOut implements SecurityEvent
{
    public function __construct(
        public string $userId,
        public string $clientIp = '',
    ) {
    }

    public function action(): string
    {
        return 'security.sign_out';
    }
}
