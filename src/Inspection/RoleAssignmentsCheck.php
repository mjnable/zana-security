<?php

declare(strict_types=1);

namespace Zana\Security\Inspection;

use Zana\Core\ApplicationInterface;
use Zana\Core\Inspection\ApplicationCheck;
use Zana\Core\Inspection\Finding;
use Zana\Core\Inspection\Severity;
use Zana\Security\RoleAssignment\RoleAssignmentStoreInterface;
use Zana\Security\RoleAssignment\Scope;

/**
 * security.role_assignments (ADR-032): the role assignment store cannot be
 * read (its table is missing, or the setting is wrong), so every scoped
 * permission check would fail. Nothing to check without a store.
 */
final readonly class RoleAssignmentsCheck implements ApplicationCheck
{
    /**
     * @param \Closure(): ?RoleAssignmentStoreInterface $store
     */
    public function __construct(private \Closure $store)
    {
    }

    public function findings(ApplicationInterface $application): array
    {
        try {
            $store = ($this->store)();
            $store?->assignmentsIn(new Scope('zana.check', 'zana.check'));
        } catch (\Throwable $e) {
            return [new Finding(
                'security.role_assignments',
                Severity::Error,
                'The role assignments cannot be read: ' . strtok($e->getMessage(), "\n"),
                hint: 'With security.role_assignments set to "database", add a migration that returns new \\Zana\\Security\\RoleAssignment\\RoleAssignmentsMigration(), and run migrate.',
            )];
        }

        return [];
    }
}
