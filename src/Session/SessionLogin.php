<?php

declare(strict_types=1);

namespace Zana\Security\Session;

use Psr\EventDispatcher\EventDispatcherInterface;
use Zana\Http\Exception\TooManyRequestsHttpException;
use Zana\Security\Event\SignedOut;
use Zana\Security\Event\SignInFailed;
use Zana\Security\Event\SignInSucceeded;
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
 * - With an event dispatcher, it dispatches SignInSucceeded, SignInFailed
 *   (wrong credentials or throttled) and SignedOut (2.15).
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
        private readonly ?EventDispatcherInterface $events = null,
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
                $this->events?->dispatch(new SignInFailed($login, SignInFailed::THROTTLED, $clientIp));
                throw new TooManyRequestsHttpException($result->resetAfter, 'Too many sign-in attempts. Please wait and try again.');
            }
        }

        $user = $this->users->findByLogin($login);
        $hash = $user === null ? null : $this->users->passwordHashFor($user);
        // Verify against a dummy hash for unknown users, so the timing does not reveal them.
        $valid = $this->hasher->verify($password, $hash ?? self::dummyHash($this->hasher)) && $hash !== null;
        if (!$valid) {
            $this->events?->dispatch(new SignInFailed($login, SignInFailed::INVALID_CREDENTIALS, $clientIp));

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
        $this->events?->dispatch(new SignInSucceeded($user->identifier(), $clientIp));

        return $user;
    }

    public function logout(string $clientIp = ''): void
    {
        $user = $this->context->user();
        $this->session->invalidate();
        $this->context->setUser(null);
        if ($user !== null) {
            $this->events?->dispatch(new SignedOut($user->identifier(), $clientIp));
        }
    }

    private static function dummyHash(PasswordHasher $hasher): string
    {
        return self::$dummyHash ??= $hasher->hash(bin2hex(random_bytes(16)));
    }
}
