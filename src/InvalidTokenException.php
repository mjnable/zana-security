<?php

declare(strict_types=1);

namespace Zana\Security;

/**
 * A bearer token was rejected. reason is MALFORMED, SIGNATURE or EXPIRED.
 */
final class InvalidTokenException extends SecurityException
{
    public const string MALFORMED = 'malformed';

    public const string SIGNATURE = 'signature';

    public const string EXPIRED = 'expired';

    public function __construct(public readonly string $reason, string $message)
    {
        parent::__construct($message);
    }
}
