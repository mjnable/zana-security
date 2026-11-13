<?php

declare(strict_types=1);

namespace Zana\Security\RoleAssignment;

use Zana\Database\ConnectionInterface;

/**
 * Role assignments in a table of the application's database (with
 * mj-zana/database): create it with RoleAssignmentsMigration. A global
 * assignment stores an empty scope, so the unique key holds on every
 * database.
 */
final readonly class DatabaseRoleAssignmentStore implements RoleAssignmentStoreInterface
{
    public const string TABLE = 'role_assignments';

    public function __construct(
        private ConnectionInterface $connection,
        private string $table = self::TABLE,
    ) {
    }

    public function rolesFor(string $userId, array $scopes = []): array
    {
        $roles = [];
        foreach ($this->assignmentsFor($userId) as $assignment) {
            $scope = $assignment->scope;
            // Type and id apart, not as one "type:id" string, which a colon could make ambiguous (2.20, S32).
            if ($scope === null || array_filter($scopes, static fn (Scope $wanted): bool => $wanted->equals($scope)) !== []) {
                $roles[$assignment->role] = true;
            }
        }

        return array_map('strval', array_keys($roles));
    }

    public function assign(string $userId, string $role, ?Scope $scope = null): void
    {
        $this->connection->table($this->table)->upsert(
            ['user_id' => $userId, 'role' => $role, 'scope_type' => $scope->type ?? '', 'scope_id' => $scope->id ?? '', 'assigned_at' => time()],
            uniqueBy: ['user_id', 'role', 'scope_type', 'scope_id'],
            update: [],
        );
    }

    public function revoke(string $userId, string $role, ?Scope $scope = null): bool
    {
        return $this->connection->table($this->table)
            ->where('user_id', $userId)->where('role', $role)
            ->where('scope_type', $scope->type ?? '')->where('scope_id', $scope->id ?? '')
            ->delete() > 0;
    }

    public function assignmentsFor(string $userId): array
    {
        return array_map(self::assignment(...), $this->connection->table($this->table)->where('user_id', $userId)->orderBy('id')->get());
    }

    public function assignmentsIn(Scope $scope): array
    {
        return array_map(self::assignment(...), $this->connection->table($this->table)
            ->where('scope_type', $scope->type)->where('scope_id', $scope->id)->orderBy('id')->get());
    }

    /**
     * @param array<string, mixed> $row
     */
    private static function assignment(array $row): RoleAssignment
    {
        $type = (string) ($row['scope_type'] ?? '');

        return new RoleAssignment((string) $row['user_id'], (string) $row['role'], $type === '' ? null : new Scope($type, (string) $row['scope_id']));
    }
}
