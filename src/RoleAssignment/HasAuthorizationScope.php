<?php

declare(strict_types=1);

namespace Zana\Security\RoleAssignment;

/**
 * A subject that belongs to a scope, so Authorizer::can($user, 'tickets.scan', $event)
 * counts the roles the user has there (2.17).
 */
interface HasAuthorizationScope
{
    public function authorizationScope(): Scope;
}
