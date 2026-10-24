<?php

declare(strict_types=1);

namespace Zana\Security\Attribute;

/**
 * The handler needs an authenticated user (otherwise 401). Checked by
 * AuthorizationMiddleware on the controller class and the method.
 */
#[\Attribute(\Attribute::TARGET_CLASS | \Attribute::TARGET_METHOD | \Attribute::TARGET_FUNCTION)]
final readonly class RequiresAuthentication
{
}
