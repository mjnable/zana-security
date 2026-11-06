<?php

declare(strict_types=1);

namespace Zana\Security\Tests;

use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Zana\Database\ConnectionFactory;
use Zana\Events\EventDispatcher;
use Zana\Events\ListenerProvider;
use Zana\Http\Exception\ForbiddenHttpException;
use Zana\Security\Attribute\RequiresPermission;
use Zana\Security\Authorizer;
use Zana\Security\Event\RoleAssigned;
use Zana\Security\Event\RoleRevoked;
use Zana\Security\Event\SecurityEvent;
use Zana\Security\Middleware\AuthorizationMiddleware;
use Zana\Security\PolicyInterface;
use Zana\Security\RoleAssignment\DatabaseRoleAssignmentStore;
use Zana\Security\RoleAssignment\HasAuthorizationScope;
use Zana\Security\RoleAssignment\InMemoryRoleAssignmentStore;
use Zana\Security\RoleAssignment\RoleAssignment;
use Zana\Security\RoleAssignment\RoleAssignments;
use Zana\Security\RoleAssignment\RoleAssignmentsMigration;
use Zana\Security\RoleAssignment\RoleAssignmentStoreInterface;
use Zana\Security\RoleAssignment\Scope;
use Zana\Security\RoleAssignment\ScopeHierarchyInterface;
use Zana\Security\SecurityContext;
use Zana\Security\SecurityException;
use Zana\Security\UserInterface;

final readonly class Person implements UserInterface
{
    /**
     * @param list<string> $roles
     */
    public function __construct(public string $id, public array $roles = [])
    {
    }

    public function identifier(): string
    {
        return $this->id;
    }

    public function roles(): array
    {
        return $this->roles;
    }
}

final readonly class TicketEvent implements HasAuthorizationScope
{
    public function __construct(public string $id)
    {
    }

    public function authorizationScope(): Scope
    {
        return new Scope('event', $this->id);
    }
}

/** Events 10 and 11 belong to organization 1, event 20 to organization 2. */
final class Venues implements ScopeHierarchyInterface
{
    public function parentsOf(Scope $scope): array
    {
        return $scope->type === 'event' ? [new Scope('organization', in_array($scope->id, ['10', '11'], true) ? '1' : '2')] : [];
    }
}

final class ScanController
{
    #[RequiresPermission('tickets.scan', scope: 'event')]
    public function scan(): void
    {
    }

    #[RequiresPermission('events.publish', scope: 'event', parameter: 'id')]
    public function publish(): void
    {
    }
}

/**
 * FE-57, ADR-032: roles everywhere or in a scope, counted by the Authorizer
 * with the scope's parents; #[RequiresPermission] with a scope from the
 * route; RoleAssignments' events; the database store on every database.
 */
final class RoleAssignmentTest extends TestCase
{
    private const array ROLES = [
        'owner' => ['events.publish', 'tickets.refund', 'staff.manage'],
        'box_office' => ['tickets.sell'],
        'scanner' => ['tickets.scan'],
        'admin' => ['*'],
    ];

    /**
     * @return array<string, array{string}>
     */
    public static function drivers(): array
    {
        return ['memory' => ['memory'], ...Databases::names()];
    }

    #[DataProvider('drivers')]
    public function testStoresKeepGlobalAndScopedAssignments(string $driver): void
    {
        $store = $this->store($driver);
        $store->assign('7', 'owner', new Scope('organization', '1'));
        $store->assign('7', 'owner', new Scope('organization', '1'));   // twice: one assignment
        $store->assign('7', 'scanner', new Scope('event', '20'));
        $store->assign('7', 'admin');
        $store->assign('8', 'box_office', new Scope('organization', '1'));

        $this->assertSame(['admin'], $store->rolesFor('7'), 'without a scope, the global roles');
        $this->assertEqualsCanonicalizing(['owner', 'admin'], $store->rolesFor('7', [new Scope('organization', '1')]));
        $this->assertEqualsCanonicalizing(['scanner', 'admin'], $store->rolesFor('7', [new Scope('event', '20'), new Scope('organization', '2')]));
        $this->assertCount(3, $store->assignmentsFor('7'));
        $this->assertEquals(
            [new RoleAssignment('7', 'owner', new Scope('organization', '1')), new RoleAssignment('8', 'box_office', new Scope('organization', '1'))],
            $store->assignmentsIn(new Scope('organization', '1')),
            "an organization's staff",
        );

        $this->assertTrue($store->revoke('7', 'admin'));
        $this->assertFalse($store->revoke('7', 'admin'));
        $this->assertFalse($store->revoke('7', 'owner'), 'the global role, not the scoped one');
        $this->assertSame(['owner'], $store->rolesFor('7', [new Scope('organization', '1')]));
    }

    public function testTheAuthorizerCountsRolesWhereTheSubjectIsAndAbove(): void
    {
        $store = new InMemoryRoleAssignmentStore();
        $store->assign('owner-1', 'owner', new Scope('organization', '1'));
        $store->assign('scanner-11', 'scanner', new Scope('event', '11'));
        $authorizer = new Authorizer(self::ROLES, [], [], $store, new Venues());
        $owner = new Person('owner-1');
        $scanner = new Person('scanner-11');

        $this->assertTrue($authorizer->can($owner, 'events.publish', new Scope('organization', '1')));
        $this->assertTrue($authorizer->can($owner, 'events.publish', new TicketEvent('10')), "an event of the owner's organization");
        $this->assertFalse($authorizer->can($owner, 'events.publish', new TicketEvent('20')), 'another organization');
        $this->assertFalse($authorizer->can($owner, 'events.publish'), 'no scope: no scoped role');

        $this->assertTrue($authorizer->can($scanner, 'tickets.scan', new TicketEvent('11')));
        $this->assertFalse($authorizer->can($scanner, 'tickets.scan', new TicketEvent('10')), 'a scanner at one event only');
        $this->assertFalse($authorizer->can($scanner, 'tickets.scan', new Scope('organization', '1')), 'roles do not flow up');
        $this->assertTrue($authorizer->can(new Person('anyone', ['scanner']), 'tickets.scan', new TicketEvent('20')), 'the user\'s own roles apply everywhere');
        $this->assertEquals([new Scope('event', '10'), new Scope('organization', '1')], $authorizer->scopesOf(new TicketEvent('10')));
    }

    public function testPoliciesStillDecideFirst(): void
    {
        $store = new InMemoryRoleAssignmentStore();
        $store->assign('7', 'owner', new Scope('organization', '1'));
        $frozen = new class implements PolicyInterface {
            public function supports(string $permission, ?object $subject): bool
            {
                return $subject instanceof Scope && $subject->type === 'organization' && $subject->id === '1';
            }

            public function decide(UserInterface $user, string $permission, ?object $subject): ?bool
            {
                return false;   // the organization is suspended
            }
        };

        $this->assertFalse((new Authorizer(self::ROLES, [], [$frozen], $store))->can(new Person('7'), 'events.publish', new Scope('organization', '1')));
    }

    public function testTheMiddlewareChecksTheScopeOfTheRoute(): void
    {
        $store = new InMemoryRoleAssignmentStore();
        $store->assign('7', 'scanner', new Scope('event', '11'));
        $store->assign('7', 'owner', new Scope('event', '30'));
        $context = new SecurityContext();
        $context->setUser(new Person('7'));
        $middleware = new AuthorizationMiddleware($context, new Authorizer(self::ROLES, [], [], $store));
        $request = static fn (string $method, array $parameters): ServerRequest => array_reduce(
            array_keys($parameters),
            static fn (ServerRequest $r, string $name): ServerRequest => $r->withAttribute($name, $parameters[$name]),
            (new ServerRequest('POST', '/'))->withAttribute('_handler', [ScanController::class, $method]),
        );

        $this->assertSame(200, $middleware->process($request('scan', ['eventId' => '11']), new PassThrough())->getStatusCode());
        $this->assertSame(200, $middleware->process($request('publish', ['id' => '30']), new PassThrough())->getStatusCode(), 'a named parameter');
        try {
            $middleware->process($request('scan', ['eventId' => '12']), new PassThrough());
            $this->fail('Not a scanner at event 12.');
        } catch (ForbiddenHttpException) {
        }

        $this->expectException(SecurityException::class);
        $this->expectExceptionMessage('needs the route parameter eventId');
        $middleware->process($request('scan', []), new PassThrough());
    }

    public function testRoleChangesAreDispatchedWithWhoMadeThem(): void
    {
        $events = [];
        $context = new SecurityContext();
        $context->setUser(new Person('owner-1'));
        $roles = new RoleAssignments(
            new InMemoryRoleAssignmentStore(),
            new EventDispatcher((new ListenerProvider())->listen(SecurityEvent::class, static function (SecurityEvent $e) use (&$events): void {
                $events[] = $e;
            })),
            $context,
        );

        $roles->assign('9', 'scanner', new Scope('event', '11'));
        $roles->assign('9', 'scanner', new Scope('event', '11'));   // already: no event
        $roles->assign('9', 'scanner');                              // a different, global assignment
        $roles->revoke('9', 'scanner', new Scope('event', '11'));
        $roles->revoke('9', 'scanner', new Scope('event', '11'));   // gone: no event

        $this->assertEquals([
            new RoleAssigned('9', 'scanner', 'event:11', 'owner-1'),
            new RoleAssigned('9', 'scanner', null, 'owner-1'),
            new RoleRevoked('9', 'scanner', 'event:11', 'owner-1'),
        ], $events);
    }

    private function store(string $driver): RoleAssignmentStoreInterface
    {
        if ($driver === 'memory') {
            return new InMemoryRoleAssignmentStore();
        }
        $settings = Databases::settings($driver);
        if (is_string($settings)) {
            $this->markTestSkipped($settings);
        }
        $db = ConnectionFactory::create($settings);
        (new RoleAssignmentsMigration())->down($db->schema());
        (new RoleAssignmentsMigration())->up($db->schema());

        return new DatabaseRoleAssignmentStore($db);
    }
}
