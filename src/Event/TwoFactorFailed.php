<?php

declare(strict_types=1);

namespace Zana\Security\Event;

/**
 * A second-factor code was refused (2.16): wrong, already used or out of its
 * window ("invalid_code"), or too many attempts ("throttled"). The code is
 * never part of the event.
 */
final readonly class TwoFactorFailed implements SecurityEvent
{
    public const string INVALID_CODE = 'invalid_code';

    public const string THROTTLED = 'throttled';

    public function __construct(
        public string $userId,
        public string $reason = self::INVALID_CODE,
        public string $clientIp = '',
    ) {
    }

    public function action(): string
    {
        return 'security.two_factor_failed';
    }
}
