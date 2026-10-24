<?php

declare(strict_types=1);

namespace Zana\Security\Tests;

use PHPUnit\Framework\TestCase;
use Zana\Http\Exception\ForbiddenHttpException;
use Zana\Http\Exception\UnauthorizedHttpException;
use Zana\Security\Authorizer;
use Zana\Security\SecurityContext;

final class AuthorizerTest extends TestCase
{
    private Authorizer $authorizer;

    protected function setUp(): void
    {
        $this->authorizer = new Authorizer(
            roles: [
                'viewer' => ['reports.view'],
                'clinician' => ['measurements.create'],
                'admin' => ['*'],
            ],
            hierarchy: [
                'clinician' => ['viewer'],
                'head' => ['clinician'],
                'loop' => ['head', 'loop'],
            ],
            policies: [new MeasurementPolicy()],
        );
    }

    public function testRolesAndHierarchy(): void
    {
        $this->assertTrue($this->authorizer->can(new User('v', ['viewer']), 'reports.view'));
        $this->assertFalse($this->authorizer->can(new User('v', ['viewer']), 'measurements.create'));
        $this->assertTrue($this->authorizer->can(new User('c', ['clinician']), 'reports.view'), 'inherited');
        $this->assertTrue($this->authorizer->can(new User('h', ['head']), 'reports.view'), 'inherited twice');
        $this->assertTrue($this->authorizer->can(new User('l', ['loop']), 'reports.view'), 'cycles are tolerated');
        $this->assertEqualsCanonicalizing(['loop', 'head', 'clinician', 'viewer'], $this->authorizer->expand('loop'));
        $this->assertFalse($this->authorizer->can(new User('n'), 'reports.view'), 'no roles');
        $this->assertFalse($this->authorizer->can(new User('u', ['unknown']), 'reports.view'));
    }

    public function testTheWildcardGrantsEverything(): void
    {
        $this->assertTrue($this->authorizer->can(new User('a', ['admin']), 'anything.at.all'));
    }

    public function testPoliciesDecideFirstAndMayAbstain(): void
    {
        $grace = new User('grace', ['viewer']);
        $admin = new User('ada', ['admin']);

        $this->assertTrue($this->authorizer->can($grace, 'measurements.edit', new Measurement('grace')), 'the policy grants');
        $this->assertFalse($this->authorizer->can($admin, 'measurements.edit', new Measurement('locked')), 'the policy denies, even admins');
        $this->assertTrue($this->authorizer->can($admin, 'measurements.edit', new Measurement('someone')), 'the policy abstains; roles decide');
        $this->assertFalse($this->authorizer->can($grace, 'measurements.edit', new Measurement('someone')));
        $this->assertTrue($this->authorizer->can($admin, 'measurements.edit'), 'unsupported without a subject');
    }

    public function testAuthorizeThrows(): void
    {
        $this->authorizer->authorize(new User('v', ['viewer']), 'reports.view');

        $this->expectException(ForbiddenHttpException::class);
        $this->authorizer->authorize(new User('v', ['viewer']), 'reports.delete');
    }

    public function testTheSecurityContext(): void
    {
        $context = new SecurityContext();
        $this->assertFalse($context->isAuthenticated());
        $this->assertNull($context->user());

        try {
            $context->requireUser();
            $this->fail('An anonymous context has no user.');
        } catch (UnauthorizedHttpException $e) {
            $this->assertSame(401, $e->status);
            $this->assertSame(['WWW-Authenticate' => 'Bearer'], $e->headers);
        }

        $user = new User('ada');
        $context->setUser($user);
        $this->assertTrue($context->isAuthenticated());
        $this->assertSame($user, $context->requireUser());
    }
}
