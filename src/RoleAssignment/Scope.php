<?php

declare(strict_types=1);

namespace Zana\Security\RoleAssignment;

/**
 * Where a role applies (FE-57, 2.17): an organization, an event, any
 * resource, by type and id. Pass it to Authorizer::can() as the subject,
 * or let the subject give it (HasAuthorizationScope).
 */
final readonly class Scope
{
    public function __construct(public string $type, public string $id)
    {
        if ($type === '' || $id === '') {
            throw new \InvalidArgumentException('A scope needs a type and an id.');
        }
    }

    public function equals(self $other): bool
    {
        return $this->type === $other->type && $this->id === $other->id;
    }

    public function __toString(): string
    {
        return "{$this->type}:{$this->id}";
    }
}
