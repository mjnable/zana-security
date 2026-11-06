<?php

declare(strict_types=1);

namespace Zana\Security\RoleAssignment;

/**
 * Where role assignments are kept (FE-57, 2.17). DatabaseRoleAssignmentStore
 * keeps them in a table (with mj-zana/database); InMemoryRoleAssignmentStore
 * is for tests. Register it as a singleton: the Authorizer is one.
 */
interface RoleAssignmentStoreInterface
{
    /**
     * The roles of the user given everywhere, or in any of $scopes.
     *
     * @param list<Scope> $scopes
     * @return list<string>
     */
    public function rolesFor(string $userId, array $scopes = []): array;

    /**
     * Give the role; giving it twice changes nothing.
     */
    public function assign(string $userId, string $role, ?Scope $scope = null): void;

    /**
     * Take the role back; true when the user had it.
     */
    public function revoke(string $userId, string $role, ?Scope $scope = null): bool;

    /**
     * @return list<RoleAssignment>
     */
    public function assignmentsFor(string $userId): array;

    /**
     * Who has which role in a scope (not its parents), e.g. an organization's staff.
     *
     * @return list<RoleAssignment>
     */
    public function assignmentsIn(Scope $scope): array;
}
