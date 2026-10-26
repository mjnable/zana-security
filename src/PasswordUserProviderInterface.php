<?php

declare(strict_types=1);

namespace Zana\Security;

/**
 * Loads users who sign in with a login (usually an email address) and a
 * password. The application implements it for SessionLogin.
 */
interface PasswordUserProviderInterface extends UserProviderInterface
{
    public function findByLogin(string $login): ?UserInterface;

    /**
     * The stored hash of the user's password, or null when the user cannot
     * sign in with a password (disabled, invited but not yet set up).
     */
    public function passwordHashFor(UserInterface $user): ?string;
}
