<?php

declare(strict_types=1);

namespace Zana\Security\RoleAssignment;

/**
 * A role given to a user, everywhere (no scope) or in one scope (2.17).
 */
final readonly class RoleAssignment
{
    public function __construct(
        public string $userId,
        public string $role,
        public ?Scope $scope = null,
    ) {
    }
}
