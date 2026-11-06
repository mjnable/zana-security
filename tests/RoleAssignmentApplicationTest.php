<?php

declare(strict_types=1);

namespace Zana\Security\Tests;

use PHPUnit\Framework\TestCase;
use Zana\Container\Contracts\ServiceCollectionInterface;
use Zana\Core\Application;
use Zana\Core\ApplicationInterface;
use Zana\Core\Inspection\ApplicationCheck;
use Zana\Core\Inspection\Finding;
use Zana\Database\ConnectionInterface;
use Zana\Database\DatabaseServiceProvider;
use Zana\Http\HttpServiceProvider;
use Zana\Security\Authorizer;
use Zana\Security\Inspection\RoleAssignmentsCheck;
use Zana\Security\RoleAssignment\RoleAssignments;
use Zana\Security\RoleAssignment\RoleAssignmentsMigration;
use Zana\Security\RoleAssignment\Scope;
use Zana\Security\RoleAssignment\ScopeHierarchyInterface;
use Zana\Security\SecurityServiceProvider;

/**
 * The provider's role assignments (ADR-032): off by default; with
 * security.role_assignments "database", the Authorizer counts the table's
 * roles with the registered scope hierarchy, and check reads the table.
 */
final class RoleAssignmentApplicationTest extends TestCase
{
    public function testTheDatabaseStoreIsUsedWhenConfigured(): void
    {
        $app = $this->app(['security.role_assignments' => 'database', 'security.roles' => ['owner' => ['events.publish']]]);
        $this->assertSame(['security.role_assignments'], $this->findings($app), 'no table yet');

        $db = $app->container()->get(ConnectionInterface::class);
        assert($db instanceof ConnectionInterface);
        (new RoleAssignmentsMigration())->up($db->schema());
        $this->assertSame([], $this->findings($app));

        $scope = $app->container()->createScope();
        $roles = $scope->get(RoleAssignments::class);
        assert($roles instanceof RoleAssignments);
        $roles->assign('7', 'owner', new Scope('organization', '1'));
        $scope->dispose();

        $authorizer = $app->container()->get(Authorizer::class);
        assert($authorizer instanceof Authorizer);
        $this->assertTrue($authorizer->can(new Person('7'), 'events.publish', new TicketEvent('10')), 'through the registered hierarchy');
        $this->assertFalse($authorizer->can(new Person('7'), 'events.publish', new TicketEvent('20')));
    }

    public function testApplicationsWithoutRoleAssignmentsAreUnchanged(): void
    {
        $app = $this->app(['security.roles' => ['editor' => ['posts.edit']]]);

        $this->assertSame([], $this->findings($app));
        $authorizer = $app->container()->get(Authorizer::class);
        assert($authorizer instanceof Authorizer);
        $this->assertTrue($authorizer->can(new Person('1', ['editor']), 'posts.edit'));
        $this->assertSame(['editor'], $authorizer->rolesOf(new Person('1', ['editor']), new Scope('organization', '1')), 'no store, no query');
    }

    /**
     * @param array<string, mixed> $config
     */
    private function app(array $config): ApplicationInterface
    {
        return Application::configure(sys_get_temp_dir() . '/zana-security-roles')->withEnvironment('testing')
            ->withConfiguration(['security.secret' => str_repeat('s', 32), 'database.connections.main' => ['driver' => 'sqlite', 'database' => ':memory:'], ...$config])
            ->withProviders(HttpServiceProvider::class, DatabaseServiceProvider::class, SecurityServiceProvider::class)
            ->withServices(static fn (ServiceCollectionInterface $s) => $s->singleton(ScopeHierarchyInterface::class, static fn (): ScopeHierarchyInterface => new Venues()))
            ->build();
    }

    /**
     * @return list<string>
     */
    private function findings(ApplicationInterface $app): array
    {
        foreach ($app->container()->tagged(ApplicationCheck::TAG) as $check) {
            if ($check instanceof RoleAssignmentsCheck) {
                return array_map(static fn (Finding $f): string => $f->id, $check->findings($app));
            }
        }
        self::fail('RoleAssignmentsCheck is not tagged.');
    }
}
