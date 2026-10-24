<?php

declare(strict_types=1);

namespace Zana\Security;

use Zana\Http\Exception\ForbiddenHttpException;

/**
 * Grants permissions: policies first (the first non-null decision wins),
 * then the user's roles, expanded through the role hierarchy. The
 * permission "*" grants everything.
 */
final class Authorizer
{
    /** @var array<string, list<string>> */
    private array $expanded = [];

    /**
     * @param array<string, list<string>> $roles role => permissions
     * @param array<string, list<string>> $hierarchy role => inherited roles
     * @param iterable<PolicyInterface> $policies
     */
    public function __construct(
        private readonly array $roles = [],
        private readonly array $hierarchy = [],
        private readonly iterable $policies = [],
    ) {
    }

    public function can(UserInterface $user, string $permission, ?object $subject = null): bool
    {
        foreach ($this->policies as $policy) {
            if ($policy->supports($permission, $subject)) {
                $decision = $policy->decide($user, $permission, $subject);
                if ($decision !== null) {
                    return $decision;
                }
            }
        }

        foreach ($user->roles() as $role) {
            foreach ($this->expand($role) as $granted) {
                $permissions = $this->roles[$granted] ?? [];
                if (in_array('*', $permissions, true) || in_array($permission, $permissions, true)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * @throws ForbiddenHttpException When the user lacks the permission
     */
    public function authorize(UserInterface $user, string $permission, ?object $subject = null): void
    {
        if (!$this->can($user, $permission, $subject)) {
            throw new ForbiddenHttpException();
        }
    }

    /**
     * The role and every role it inherits, directly or not.
     *
     * @return list<string>
     */
    public function expand(string $role): array
    {
        if (isset($this->expanded[$role])) {
            return $this->expanded[$role];
        }

        $found = [];
        $pending = [$role];
        while ($pending !== []) {
            $current = array_pop($pending);
            if (isset($found[$current])) {
                continue;
            }
            $found[$current] = true;
            array_push($pending, ...($this->hierarchy[$current] ?? []));
        }

        return $this->expanded[$role] = array_map('strval', array_keys($found));
    }
}
