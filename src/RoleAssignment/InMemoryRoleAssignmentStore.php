<?php

declare(strict_types=1);

namespace Zana\Security\RoleAssignment;

/**
 * Role assignments for the life of the process: for tests.
 */
final class InMemoryRoleAssignmentStore implements RoleAssignmentStoreInterface
{
    /** @var array<string, RoleAssignment> */
    private array $assignments = [];

    public function rolesFor(string $userId, array $scopes = []): array
    {
        $roles = [];
        foreach ($this->assignments as $assignment) {
            if ($assignment->userId !== $userId) {
                continue;
            }
            $scope = $assignment->scope;
            if ($scope === null || array_filter($scopes, static fn (Scope $s): bool => $s->equals($scope)) !== []) {
                $roles[$assignment->role] = true;
            }
        }

        return array_map('strval', array_keys($roles));
    }

    public function assign(string $userId, string $role, ?Scope $scope = null): void
    {
        $this->assignments[self::key($userId, $role, $scope)] = new RoleAssignment($userId, $role, $scope);
    }

    public function revoke(string $userId, string $role, ?Scope $scope = null): bool
    {
        $key = self::key($userId, $role, $scope);
        $had = isset($this->assignments[$key]);
        unset($this->assignments[$key]);

        return $had;
    }

    public function assignmentsFor(string $userId): array
    {
        return array_values(array_filter($this->assignments, static fn (RoleAssignment $a): bool => $a->userId === $userId));
    }

    public function assignmentsIn(Scope $scope): array
    {
        return array_values(array_filter($this->assignments, static fn (RoleAssignment $a): bool => $a->scope?->equals($scope) === true));
    }

    private static function key(string $userId, string $role, ?Scope $scope): string
    {
        return $userId . "\n" . $role . "\n" . ($scope === null ? '' : (string) $scope);
    }
}
