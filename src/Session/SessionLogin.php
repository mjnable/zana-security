<?php

declare(strict_types=1);

namespace Zana\Security\Session;

use Psr\EventDispatcher\EventDispatcherInterface;
use Zana\Http\Exception\TooManyRequestsHttpException;
use Zana\Security\Event\SignedOut;
use Zana\Security\Event\SignInFailed;
use Zana\Security\Event\SignInSucceeded;
use Zana\Security\InvalidTokenException;
use Zana\Security\PasswordHasher;
use Zana\Security\PasswordUpgraderInterface;
use Zana\Security\PasswordUserProviderInterface;
use Zana\Security\RateLimit\RateLimiter;
use Zana\Security\SecurityContext;
use Zana\Security\TokenSigner;
use Zana\Security\TwoFactor\TwoFactor;
use Zana\Security\UserInterface;
use Zana\Session\SessionInterface;

/**
 * Signs users in and out of a session-based back office (FE-28), with a
 * second factor when they have one (FE-56, 2.16):
 *
 *     $result = $login->start($input->string('email'), $input->string('password'), $context->clientIp(), $deviceCookie);
 *     if ($result->needsSecondFactor()) { … show the code form … }
 *     $result = $login->completeSecondFactor($input->string('code'), $context->clientIp(), remember: true);
 *     if ($result->deviceToken !== null) { … set the "remember this device" cookie … }
 *
 * - A failed attempt never says whether the account exists, and takes as
 *   long when it does not (a password is verified either way).
 * - Attempts are limited per login from one client address
 *   (security.login.max_attempts per security.login.window seconds), per
 *   login from every address together (security.login.max_attempts_per_login,
 *   ten times as many by default), per client address, and second-factor
 *   attempts per user (2.28). Before 2.28 the first limit was per login from
 *   every address, so anyone could lock the owner out with five wrong
 *   passwords; now they lock out only themselves, and need many addresses
 *   to reach the owner.
 * - A browser that signed in before is not locked out at all (2.28): each
 *   sign-in gives LoginResult::$knownDevice, a token the application sets in
 *   a cookie and passes back to start(). It lets that browser through the
 *   per-login limit, for that login only; it never replaces the password.
 * - A user with a second factor is not signed in by the password alone: the
 *   session holds a pending sign-in for 5 minutes, until a code completes it,
 *   unless the device was remembered.
 * - The session gets a new id at each step, against session fixation.
 * - The session remembers a fingerprint of the password hash, so a password
 *   change signs out every other session (2.19.1).
 * - The address limit counts failed attempts only, so a sign-in to one's own
 *   account does not reset it, and it applies only when an address is given
 *   (2.19.1).
 * - Passwords hashed with old settings are rehashed when the provider
 *   implements PasswordUpgraderInterface.
 * - With an event dispatcher, it dispatches SignInSucceeded, SignInFailed
 *   (wrong credentials or throttled) and SignedOut (2.15).
 */
final class SessionLogin
{
    public const string SESSION_KEY = '_security.user';

    public const string PENDING_KEY = '_security.two_factor.user';

    public const string PASSWORD_KEY = '_security.password';

    private const string PENDING_AT_KEY = '_security.two_factor.at';

    private const int PENDING_SECONDS = 300;

    private static ?string $dummyHash = null;

    /**
     * @param (\Closure(): int)|null $clock
     */
    public function __construct(
        private readonly PasswordUserProviderInterface $users,
        private readonly PasswordHasher $hasher,
        private readonly SessionInterface $session,
        private readonly SecurityContext $context,
        private readonly ?RateLimiter $limiter = null,
        private readonly int $maxAttempts = 5,
        private readonly int $window = 900,
        private readonly ?EventDispatcherInterface $events = null,
        private readonly ?TwoFactor $twoFactor = null,
        private readonly ?\Closure $clock = null,
        private readonly ?int $maxAttemptsPerLogin = null,
        private readonly ?TokenSigner $knownDevices = null,
        private readonly int $knownDeviceLifetime = self::KNOWN_DEVICE_LIFETIME,
    ) {
    }

    /** 90 days. */
    public const int KNOWN_DEVICE_LIFETIME = 7_776_000;

    private const string KNOWN_DEVICE_PREFIX = 'known-device:';

    /**
     * Sign in with a password; null when it fails, or when the user must
     * still give a second-factor code (see start() and hasPendingSecondFactor()).
     *
     * @throws TooManyRequestsHttpException After too many failed attempts
     */
    public function attempt(string $login, string $password, string $clientIp = ''): ?UserInterface
    {
        return $this->start($login, $password, $clientIp)->user;
    }

    /**
     * The first step: the password. Signs the user in, or asks for a second factor.
     *
     * @param string|null $deviceToken The "remember this device" cookie, which skips the second factor
     * @param string|null $knownDevice The "known device" cookie (2.28), LoginResult::$knownDevice of an earlier
     *        sign-in: this browser is not held by the limit on the login from every address
     *
     * @throws TooManyRequestsHttpException After too many failed attempts
     */
    public function start(string $login, #[\SensitiveParameter] string $password, string $clientIp = '', ?string $deviceToken = null, #[\SensitiveParameter] ?string $knownDevice = null): LoginResult
    {
        $this->session->remove(self::PENDING_KEY);
        $loginKey = 'login:' . strtolower(trim($login));
        $addressKey = $clientIp === '' ? null : 'login-ip:' . $clientIp;
        // 2.28: five tries per login from one address lock out that address only; the login itself, from every
        // address together, takes ten times as many, and never holds a browser that signed in to it before.
        $results = [
            $addressKey === null ? null : $this->limiter?->peek($addressKey, $this->maxAttempts, $this->window),
            $this->limiter?->attempt($addressKey === null ? $loginKey : "{$loginKey}|{$clientIp}", $this->maxAttempts, $this->window),
            $addressKey === null || $this->isKnownDevice($login, $knownDevice) ? null : $this->limiter?->attempt($loginKey, $this->maxAttemptsPerLogin(), $this->window),
        ];
        foreach ($results as $result) {
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
            if ($addressKey !== null) {
                $this->limiter?->attempt($addressKey, $this->maxAttempts, $this->window);
            }
            $this->events?->dispatch(new SignInFailed($login, SignInFailed::INVALID_CREDENTIALS, $clientIp));

            return new LoginResult(LoginResult::FAILED);
        }

        $this->limiter?->reset($loginKey, $this->window);
        if ($addressKey !== null) {
            $this->limiter?->reset("{$loginKey}|{$clientIp}", $this->window);
        }
        if ($this->users instanceof PasswordUpgraderInterface && $this->hasher->needsRehash($hash)) {
            $this->users->upgradePassword($user, $this->hasher->hash($password));
        }

        if ($this->twoFactor !== null && $this->twoFactor->enabled($user)) {
            if ($this->twoFactor->rememberedDevice($user, $deviceToken)) {
                return $this->signIn($user, $clientIp, 'session+remembered_device');
            }
            $this->session->regenerate();
            $this->session->set(self::PENDING_KEY, $user->identifier());
            $this->session->set(self::PENDING_AT_KEY, $this->now());

            return new LoginResult(LoginResult::SECOND_FACTOR_REQUIRED, null);
        }

        return $this->signIn($user, $clientIp, 'session');
    }

    /**
     * Whether a password was accepted and the session waits for a second-factor code.
     */
    public function hasPendingSecondFactor(): bool
    {
        return $this->pendingUser() !== null;
    }

    /**
     * The second step: a code from the authenticator app, or a recovery code.
     *
     * @param bool $remember Also return a device token for a "remember this device" cookie
     *
     * @throws TooManyRequestsHttpException After too many failed codes
     */
    public function completeSecondFactor(string $code, string $clientIp = '', bool $remember = false): LoginResult
    {
        $user = $this->pendingUser();
        if ($user === null || $this->twoFactor === null) {
            return new LoginResult(LoginResult::FAILED);
        }
        if (!$this->twoFactor->verify($user, $code, $clientIp)) {
            return new LoginResult(LoginResult::FAILED);
        }

        $result = $this->signIn($user, $clientIp, 'session+two_factor');

        return $remember ? new LoginResult(LoginResult::SIGNED_IN, $user, $this->twoFactor->deviceToken($user), $result->knownDevice) : $result;
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

    private function signIn(UserInterface $user, string $clientIp, string $method): LoginResult
    {
        $this->session->remove(self::PENDING_KEY);
        $this->session->remove(self::PENDING_AT_KEY);
        $this->session->regenerate();
        $this->session->set(self::SESSION_KEY, $user->identifier());
        $this->session->set(self::PASSWORD_KEY, self::passwordFingerprint($this->users->passwordHashFor($user)));
        $this->context->setUser($user);
        $this->events?->dispatch(new SignInSucceeded($user->identifier(), $clientIp, $method));

        return new LoginResult(LoginResult::SIGNED_IN, $user, knownDevice: $this->knownDeviceToken($user));
    }

    private function maxAttemptsPerLogin(): int
    {
        return $this->maxAttemptsPerLogin ?? $this->maxAttempts * 10;
    }

    /**
     * A token for the "known device" cookie (2.28): names the user by a hash of their identifier, so the cookie
     * says nothing about who they are. Its subject has a colon, so it never counts as a bearer token.
     */
    private function knownDeviceToken(UserInterface $user): ?string
    {
        return $this->knownDevices?->issue(self::KNOWN_DEVICE_PREFIX . self::deviceName($user), $this->knownDeviceLifetime);
    }

    /**
     * Whether the cookie is a known device of the user of this login. The user is looked up only when a cookie
     * is sent, so a request without one costs what it did.
     */
    private function isKnownDevice(string $login, ?string $token): bool
    {
        if ($this->knownDevices === null || $token === null || $token === '') {
            return false;
        }
        try {
            $subject = $this->knownDevices->verify($token)->subject;
        } catch (InvalidTokenException) {
            return false;
        }
        // Another of Zana's tokens (a CSRF, reset or second-factor device token, a bearer token) has another subject.
        $user = $this->users->findByLogin($login);

        return $user !== null && hash_equals(self::KNOWN_DEVICE_PREFIX . self::deviceName($user), $subject);
    }

    private static function deviceName(UserInterface $user): string
    {
        return hash('sha256', 'zana.known-device|' . $user->identifier());
    }

    private function pendingUser(): ?UserInterface
    {
        $id = $this->session->get(self::PENDING_KEY);
        $at = $this->session->get(self::PENDING_AT_KEY);
        if (!is_string($id) || !is_int($at)) {
            return null;
        }
        if ($this->now() - $at > self::PENDING_SECONDS) {
            $this->session->remove(self::PENDING_KEY);
            $this->session->remove(self::PENDING_AT_KEY);

            return null;
        }

        return $this->users->findByIdentifier($id);
    }

    private function now(): int
    {
        return $this->clock === null ? time() : ($this->clock)();
    }

    /**
     * What the session remembers of the password: it changes with the hash, so
     * SessionAuthenticationMiddleware signs out sessions from before a change.
     */
    public static function passwordFingerprint(?string $hash): string
    {
        return hash('sha256', 'zana.session.password|' . ($hash ?? ''));
    }

    private static function dummyHash(PasswordHasher $hasher): string
    {
        return self::$dummyHash ??= $hasher->hash(bin2hex(random_bytes(16)));
    }
}
