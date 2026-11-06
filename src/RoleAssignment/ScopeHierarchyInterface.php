<?php

declare(strict_types=1);

namespace Zana\Security\RoleAssignment;

/**
 * The scopes that contain a scope (2.17): an event belongs to an
 * organization, so the organization's owner has their roles at its events.
 * Register an implementation in the container; without one, scopes have no
 * parents.
 */
interface ScopeHierarchyInterface
{
    /**
     * The direct parents; they may have parents of their own.
     *
     * @return list<Scope>
     */
    public function parentsOf(Scope $scope): array;
}
