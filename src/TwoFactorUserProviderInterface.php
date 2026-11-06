<?php

declare(strict_types=1);

namespace Zana\Security;

/**
 * Stores each user's second factor (FE-56, 2.16), as PasswordUserProviderInterface
 * stores the password hash. The state is one opaque, encrypted string: keep it
 * in a nullable text column of the user table, and never read it yourself.
 */
interface TwoFactorUserProviderInterface extends UserProviderInterface
{
    /**
     * The stored state, or null when the user has no second factor.
     */
    public function twoFactorStateFor(UserInterface $user): ?string;

    /**
     * Store the state; null removes the second factor.
     */
    public function saveTwoFactorState(UserInterface $user, ?string $state): void;
}
