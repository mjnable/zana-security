<?php

declare(strict_types=1);

namespace Zana\Security\Attribute;

/**
 * The handler needs an authenticated user (otherwise 401) who has this
 * permission (otherwise 403). Repeatable; every permission is required.
 */
#[\Attribute(\Attribute::TARGET_CLASS | \Attribute::TARGET_METHOD | \Attribute::TARGET_FUNCTION | \Attribute::IS_REPEATABLE)]
final readonly class RequiresPermission
{
    public function __construct(public string $permission)
    {
    }
}
