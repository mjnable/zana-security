<?php

declare(strict_types=1);

namespace Zana\Security;

/**
 * Security is misconfigured or misused (a short secret, a password that is too long, ...).
 */
class SecurityException extends \RuntimeException
{
}
