<?php

declare(strict_types=1);

namespace Zana\Security;

/**
 * Implemented by a PasswordUserProviderInterface that can store a new hash:
 * SessionLogin then rehashes passwords made with old algorithms or options
 * when their users sign in.
 */
interface PasswordUpgraderInterface
{
    public function upgradePassword(UserInterface $user, string $newHash): void;
}
