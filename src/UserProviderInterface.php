<?php

declare(strict_types=1);

namespace Zana\Security;

/**
 * Loads users for authentication. The application implements and registers it.
 */
interface UserProviderInterface
{
    public function findByIdentifier(string $identifier): ?UserInterface;
}
