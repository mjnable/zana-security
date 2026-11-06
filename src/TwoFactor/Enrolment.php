<?php

declare(strict_types=1);

namespace Zana\Security\TwoFactor;

/**
 * What a user needs to set up a second factor: the secret (to type in), the
 * otpauth:// URI (to show as a QR code) and the recovery codes (to keep).
 * Show them once; they are stored encrypted and hashed.
 */
final readonly class Enrolment
{
    /**
     * @param list<string> $recoveryCodes
     */
    public function __construct(
        #[\SensitiveParameter] public string $secret,
        public string $uri,
        public array $recoveryCodes,
    ) {
    }
}
