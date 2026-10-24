<?php

declare(strict_types=1);

namespace Zana\Security\Tests;

use Zana\Security\Attribute\RequiresAuthentication;
use Zana\Security\Attribute\RequiresPermission;
use Zana\Security\PolicyInterface;
use Zana\Security\SecurityContext;
use Zana\Security\UserInterface;
use Zana\Security\UserProviderInterface;

final readonly class User implements UserInterface
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

final class Users implements UserProviderInterface
{
    /** @var array<string, User> */
    public array $users;

    public function __construct()
    {
        $this->users = [
            'ada' => new User('ada', ['admin']),
            'grace' => new User('grace', ['clinician']),
            'alan' => new User('alan'),
        ];
    }

    public function findByIdentifier(string $identifier): ?UserInterface
    {
        return $this->users[$identifier] ?? null;
    }
}

final readonly class Measurement
{
    public function __construct(public string $ownerId)
    {
    }
}

/**
 * Owners may always edit their own measurements; nobody may edit locked ones.
 */
final class MeasurementPolicy implements PolicyInterface
{
    public function supports(string $permission, ?object $subject): bool
    {
        return $permission === 'measurements.edit' && $subject instanceof Measurement;
    }

    public function decide(UserInterface $user, string $permission, ?object $subject): ?bool
    {
        assert($subject instanceof Measurement);

        return match (true) {
            $subject->ownerId === 'locked' => false,
            $subject->ownerId === $user->identifier() => true,
            default => null,
        };
    }
}

final class PublicController
{
    public function __invoke(): string
    {
        return 'public';
    }
}

#[RequiresAuthentication]
final class ProfileController
{
    public function show(SecurityContext $context): string
    {
        return 'profile:' . $context->requireUser()->identifier();
    }
}

#[RequiresPermission('reports.view')]
final class ReportController
{
    public function index(): string
    {
        return 'reports';
    }

    #[RequiresPermission('reports.export')]
    public function export(): string
    {
        return 'export';
    }
}
