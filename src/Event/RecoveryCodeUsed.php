<?php

declare(strict_types=1);

namespace Zana\Security\Event;

/**
 * A user signed in with a recovery code, which is now used up (2.16).
 */
final readonly class RecoveryCodeUsed implements SecurityEvent
{
    public function __construct(
        public string $userId,
        public int $remaining,
        public string $clientIp = '',
    ) {
    }

    public function action(): string
    {
        return 'security.recovery_code_used';
    }
}
