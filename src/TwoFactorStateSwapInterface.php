<?php

declare(strict_types=1);

namespace Zana\Security;

/**
 * Optional, for a user provider that stores second factors (2.20, S14):
 * replace the stored state only if it is still the one that was read.
 *
 * Without it, two sign-ins at the same moment both read the state, and the
 * one that writes last wins: a recovery code the other one used comes back,
 * and a TOTP code can count twice. With it, the second write fails, and its
 * code is refused, so the person tries again.
 *
 * In SQL: UPDATE users SET two_factor = :new WHERE id = :id AND two_factor = :expected
 * (or IS NULL), and return whether one row changed.
 */
interface TwoFactorStateSwapInterface extends TwoFactorUserProviderInterface
{
    /**
     * Store $new only if the stored state is still $expected; whether it was stored.
     */
    public function swapTwoFactorState(UserInterface $user, ?string $expected, ?string $new): bool;
}
