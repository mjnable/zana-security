<?php

declare(strict_types=1);

namespace Zana\Security\Session;

use Zana\Security\UserInterface;

/**
 * What SessionLogin::start() and completeSecondFactor() did (2.16): signed
 * the user in, asks for a second-factor code, or failed. A device token is
 * set when the user asked to remember the device: put it in a cookie.
 */
final readonly class LoginResult
{
    public const string SIGNED_IN = 'signed_in';

    public const string SECOND_FACTOR_REQUIRED = 'second_factor_required';

    public const string FAILED = 'failed';

    public function __construct(
        public string $status,
        public ?UserInterface $user = null,
        #[\SensitiveParameter] public ?string $deviceToken = null,
    ) {
    }

    public function signedIn(): bool
    {
        return $this->status === self::SIGNED_IN;
    }

    public function needsSecondFactor(): bool
    {
        return $this->status === self::SECOND_FACTOR_REQUIRED;
    }
}
