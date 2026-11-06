<?php

declare(strict_types=1);

namespace Zana\Security\RoleAssignment;

use Zana\Database\Migration\Migration;
use Zana\Database\Schema\Blueprint;
use Zana\Database\Schema\Schema;

/**
 * The role_assignments table (2.17), for DatabaseRoleAssignmentStore. Return
 * it from a file in database/migrations:
 *
 *     return new \Zana\Security\RoleAssignment\RoleAssignmentsMigration();
 */
final class RoleAssignmentsMigration extends Migration
{
    public function __construct(private readonly string $table = DatabaseRoleAssignmentStore::TABLE)
    {
    }

    public function up(Schema $schema): void
    {
        $table = $this->table;
        $schema->create($table, static function (Blueprint $t) use ($table): void {
            $t->id();
            $t->string('user_id', 190);
            $t->string('role', 100);
            $t->string('scope_type', 100)->default('');
            $t->string('scope_id', 190)->default('');
            $t->bigInteger('assigned_at');
            $t->unique(['user_id', 'role', 'scope_type', 'scope_id'], "{$table}_unique");
            $t->index(['scope_type', 'scope_id'], "{$table}_scope_index");
        });
    }

    public function down(Schema $schema): void
    {
        $schema->dropIfExists($this->table);
    }
}
