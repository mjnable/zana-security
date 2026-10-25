<?php

declare(strict_types=1);

namespace Zana\Security\Attribute;

use Attribute;

/**
 * Skips CsrfMiddleware for a handler, e.g. a webhook that is verified by its
 * own signature. The middleware must run as route middleware to see it.
 */
#[Attribute(Attribute::TARGET_CLASS | Attribute::TARGET_METHOD | Attribute::TARGET_FUNCTION)]
final readonly class WithoutCsrf
{
}
