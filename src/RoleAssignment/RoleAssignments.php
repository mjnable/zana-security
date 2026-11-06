<?php

declare(strict_types=1);

namespace Zana\Security\RoleAssignment;

use Psr\EventDispatcher\EventDispatcherInterface;
use Zana\Security\Event\RoleAssigned;
use Zana\Security\Event\RoleRevoked;
use Zana\Security\SecurityContext;

/**
 * Gives and takes back roles (FE-57, 2.17), everywhere or in a scope:
 *
 *     $roles->assign($userId, 'owner', new Scope('organization', $orgId));
 *     $roles->assign($userId, 'scanner', new Scope('event', $eventId));
 *
 * Registered scoped: RoleAssigned and RoleRevoked name the signed-in user
 * who made the change, and mj-zana/audit records them.
 */
final readonly class RoleAssignments
{
    public function __construct(
        private RoleAssignmentStoreInterface $store,
        private ?EventDispatcherInterface $events = null,
        private ?SecurityContext $context = null,
    ) {
    }

    public function assign(string $userId, string $role, ?Scope $scope = null): void
    {
        $same = static fn (RoleAssignment $a): bool => $a->role === $role
            && ($a->scope === null || $scope === null ? $a->scope === $scope : $a->scope->equals($scope));
        $had = array_filter($this->store->assignmentsFor($userId), $same) !== [];
        $this->store->assign($userId, $role, $scope);
        if (!$had) {
            $this->events?->dispatch(new RoleAssigned($userId, $role, $scope === null ? null : (string) $scope, $this->context?->user()?->identifier()));
        }
    }

    public function revoke(string $userId, string $role, ?Scope $scope = null): bool
    {
        $revoked = $this->store->revoke($userId, $role, $scope);
        if ($revoked) {
            $this->events?->dispatch(new RoleRevoked($userId, $role, $scope === null ? null : (string) $scope, $this->context?->user()?->identifier()));
        }

        return $revoked;
    }

    /**
     * @return list<RoleAssignment>
     */
    public function assignmentsFor(string $userId): array
    {
        return $this->store->assignmentsFor($userId);
    }

    /**
     * @return list<RoleAssignment>
     */
    public function assignmentsIn(Scope $scope): array
    {
        return $this->store->assignmentsIn($scope);
    }
}
