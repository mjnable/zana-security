<?php

declare(strict_types=1);

namespace Zana\Security\Event;

/**
 * A role was taken back from a user (2.17). $byUserId is whoever was signed
 * in when it happened.
 */
final readonly class RoleRevoked implements SecurityEvent
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
        return 'security.role_revoked';
    }
}
