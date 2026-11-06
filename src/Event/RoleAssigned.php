<?php

declare(strict_types=1);

namespace Zana\Security\Event;

/**
 * A role was given to a user, everywhere or in a scope (2.17). $byUserId is
 * whoever was signed in when it happened.
 */
final readonly class RoleAssigned implements SecurityEvent
{
    public function __construct(
        public string $userId,
        public string $role,
        public ?string $scope = null,
        public ?string $byUserId = null,
    ) {
    }

    public function action(): string
    {
        return 'security.role_assigned';
    }
}
