<?php

declare(strict_types=1);

namespace Zana\Security;

/**
 * Decides permissions that depend on the subject, e.g. "a clinician may edit
 * their own patients' measurements".
 */
interface PolicyInterface
{
    public function supports(string $permission, ?object $subject): bool;

    /**
     * @return bool|null true grants, false denies, null abstains (the next
     *                   policy, then the user's roles decide)
     */
    public function decide(UserInterface $user, string $permission, ?object $subject): ?bool;
}
