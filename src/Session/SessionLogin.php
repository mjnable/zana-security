<?php

declare(strict_types=1);

namespace Zana\Security\Session;

use Zana\Http\Exception\TooManyRequestsHttpException;
use Zana\Security\PasswordHasher;
use Zana\Security\PasswordUpgraderInterface;
use Zana\Security\PasswordUserProviderInterface;
use Zana\Security\RateLimit\RateLimiter;
use Zana\Security\SecurityContext;
use Zana\Security\UserInterface;
use Zana\Session\SessionInterface;

/**
 * Signs users in and out of a session-based back office (FE-28):
 *
 *     $user = $login->attempt($input->string('email'), $input->string('password'), $context->clientIp());
 *     if ($user === null) { … show "Wrong email or password." … }
 *
 * - A failed attempt never says whether the account exists, and takes as
 *   long when it does not (a password is verified either way).
 * - Attempts are limited per login and per client address
 *   (security.login.max_attempts per security.login.window seconds).
 * - The session gets a new id at login, against session fixation.
 * - Passwords hashed with old settings are rehashed when the provider
 *   implements PasswordUpgraderInterface.
 */
final class SessionLogin
{
    public const string SESSION_KEY = '_security.user';

    private static ?string $dummyHash = null;

    public function __construct(
        private readonly PasswordUserProviderInterface $users,
        private readonly PasswordHasher $hasher,
        private readonly SessionInterface $session,
        private readonly SecurityContext $context,
        private readonly ?RateLimiter $limiter = null,
        private readonly int $maxAttempts = 5,
        private readonly int $window = 900,
    ) {
    }

    /**
     * @throws TooManyRequestsHttpException After too many failed attempts
     */
    public function attempt(string $login, string $password, string $clientIp = ''): ?UserInterface
    {
        $keys = ['login:' . strtolower(trim($login)), 'login-ip:' . $clientIp];
        foreach ($keys as $key) {
            $result = $this->limiter?->attempt($key, $this->maxAttempts, $this->window);
            if ($result !== null && !$result->allowed) {
                throw new TooManyRequestsHttpException($result->resetAfter, 'Too many sign-in attempts. Please wait and try again.');
            }
        }

        $user = $this->users->findByLogin($login);
        $hash = $user === null ? null : $this->users->passwordHashFor($user);
        // Verify against a dummy hash for unknown users, so the timing does not reveal them.
        $valid = $this->hasher->verify($password, $hash ?? self::dummyHash($this->hasher)) && $hash !== null;
        if (!$valid) {
            return null;
        }

        foreach ($keys as $key) {
            $this->limiter?->reset($key, $this->window);
        }
        if ($this->users instanceof PasswordUpgraderInterface && $this->hasher->needsRehash($hash)) {
            $this->users->upgradePassword($user, $this->hasher->hash($password));
        }

        $this->session->regenerate();
        $this->session->set(self::SESSION_KEY, $user->identifier());
        $this->context->setUser($user);

        return $user;
    }

    public function logout(): void
    {
        $this->session->invalidate();
        $this->context->setUser(null);
    }

    private static function dummyHash(PasswordHasher $hasher): string
    {
        return self::$dummyHash ??= $hasher->hash(bin2hex(random_bytes(16)));
    }
}
