<?php

declare(strict_types=1);

namespace Zana\Security\TwoFactor;

use Psr\EventDispatcher\EventDispatcherInterface;
use Zana\Http\Exception\TooManyRequestsHttpException;
use Zana\Security\Event\RecoveryCodeUsed;
use Zana\Security\Event\TwoFactorDisabled;
use Zana\Security\Event\TwoFactorEnabled;
use Zana\Security\Event\TwoFactorFailed;
use Zana\Security\Internal\SecretBox;
use Zana\Security\InvalidTokenException;
use Zana\Security\RateLimit\RateLimiter;
use Zana\Security\SecurityException;
use Zana\Security\TokenSigner;
use Zana\Security\TwoFactorUserProviderInterface;
use Zana\Security\UserInterface;

/**
 * Second factors (FE-56, ADR-031): TOTP from an authenticator app, with
 * recovery codes.
 *
 *     $enrolment = $twoFactor->enrol($user);        // show $enrolment->uri as a QR code, and the recovery codes
 *     $twoFactor->confirm($user, $codeFromTheApp);  // now SessionLogin asks for a code after the password
 *
 * - The state is sealed with security.two_factor.key and kept by the user
 *   provider (TwoFactorUserProviderInterface).
 * - A code is accepted one step (30 seconds) early or late, and only once.
 * - Recovery codes are stored as HMACs, and each works once.
 * - Attempts are limited per user (security.two_factor.max_attempts per
 *   security.two_factor.window seconds).
 * - A state that cannot be opened, because the key changed or the state was
 *   damaged, still counts as a second factor, and no code passes it: the
 *   sign-in fails closed (2.19.1).
 */
final readonly class TwoFactor
{
    private const int RECOVERY_CODES = 10;

    private const string DEVICE_PREFIX = 'device:';

    private SecretBox $box;

    /**
     * @param string $key security.two_factor.key: at least 32 characters, kept for good
     */
    public function __construct(
        private TwoFactorUserProviderInterface $users,
        #[\SensitiveParameter] string $key,
        private TokenSigner $signer,
        private Totp $totp = new Totp(),
        private ?RateLimiter $limiter = null,
        private ?EventDispatcherInterface $events = null,
        private string $issuer = 'Zana',
        private int $maxAttempts = 5,
        private int $window = 900,
        private int $rememberDays = 30,
    ) {
        $this->box = new SecretBox($key);
    }

    /**
     * Start enrolment: a new secret and recovery codes, kept unconfirmed until confirm().
     *
     * @param string|null $account The name shown in the authenticator app; the user identifier by default
     */
    public function enrol(UserInterface $user, ?string $account = null): Enrolment
    {
        if ($this->enabled($user)) {
            throw new SecurityException('This user already has a second factor, or one that cannot be read with this key; disable it before enrolling again.');
        }
        $secret = $this->totp->generateSecret();
        $codes = self::newRecoveryCodes();
        $this->save($user, new Internal\State($secret, array_map($this->recoveryHash(...), $codes)));

        return new Enrolment($secret, $this->totp->uri($secret, $this->issuer, $account ?? $user->identifier()), $codes);
    }

    /**
     * Finish enrolment with a code from the app; false when it is wrong.
     */
    public function confirm(UserInterface $user, string $code): bool
    {
        $state = $this->state($user);
        if ($state === null || $state->confirmed) {
            return false;
        }
        $step = $this->totp->verify($state->secret, $code, $state->lastStep);
        if ($step === null) {
            return false;
        }
        $this->save($user, $state->with(lastStep: $step, confirmed: true));
        $this->events?->dispatch(new TwoFactorEnabled($user->identifier()));

        return true;
    }

    public function enabled(UserInterface $user): bool
    {
        if ($this->unreadable($user)) {
            return true;
        }

        return $this->state($user)?->confirmed === true;
    }

    /**
     * Check a code from the app, or a recovery code.
     *
     * @throws TooManyRequestsHttpException After too many failed attempts
     */
    public function verify(UserInterface $user, string $code, string $clientIp = ''): bool
    {
        $key = 'two-factor:' . $user->identifier();
        $limit = $this->limiter?->attempt($key, $this->maxAttempts, $this->window);
        if ($limit !== null && !$limit->allowed) {
            $this->events?->dispatch(new TwoFactorFailed($user->identifier(), TwoFactorFailed::THROTTLED, $clientIp));
            throw new TooManyRequestsHttpException($limit->resetAfter, 'Too many attempts. Please wait and try again.');
        }

        if ($this->unreadable($user)) {
            $this->events?->dispatch(new TwoFactorFailed($user->identifier(), TwoFactorFailed::UNREADABLE, $clientIp));

            return false;
        }
        $state = $this->state($user);
        if ($state === null || !$state->confirmed) {
            return false;
        }
        $step = $this->totp->verify($state->secret, $code, $state->lastStep);
        if ($step !== null) {
            $this->save($user, $state->with(lastStep: $step));
            $this->limiter?->reset($key, $this->window);

            return true;
        }

        $hash = $this->recoveryHash($code);
        $remaining = array_values(array_filter($state->recoveryHashes, static fn (string $h): bool => !hash_equals($h, $hash)));
        if (count($remaining) < count($state->recoveryHashes)) {
            $this->save($user, $state->with(recoveryHashes: $remaining));
            $this->limiter?->reset($key, $this->window);
            $this->events?->dispatch(new RecoveryCodeUsed($user->identifier(), count($remaining), $clientIp));

            return true;
        }

        $this->events?->dispatch(new TwoFactorFailed($user->identifier(), TwoFactorFailed::INVALID_CODE, $clientIp));

        return false;
    }

    public function disable(UserInterface $user): void
    {
        $had = $this->enabled($user);
        $this->users->saveTwoFactorState($user, null);
        if ($had) {
            $this->events?->dispatch(new TwoFactorDisabled($user->identifier()));
        }
    }

    /**
     * New recovery codes, replacing the old ones. Show them once.
     *
     * @return list<string>
     */
    public function regenerateRecoveryCodes(UserInterface $user): array
    {
        $state = $this->state($user) ?? throw new SecurityException('This user has no second factor.');
        $codes = self::newRecoveryCodes();
        $this->save($user, $state->with(recoveryHashes: array_map($this->recoveryHash(...), $codes)));

        return $codes;
    }

    public function remainingRecoveryCodes(UserInterface $user): int
    {
        return count($this->state($user)->recoveryHashes ?? []);
    }

    /**
     * A signed token for a "remember this device" cookie (security.two_factor.remember_days);
     * it stops working when the user enrols again.
     */
    public function deviceToken(UserInterface $user): string
    {
        $state = $this->state($user) ?? throw new SecurityException('This user has no second factor.');

        return $this->signer->issue(self::DEVICE_PREFIX . $user->identifier(), $this->rememberDays * 86_400, ['f' => $state->fingerprint()]);
    }

    public function rememberedDevice(UserInterface $user, ?string $token): bool
    {
        $state = $this->state($user);
        if ($token === null || $token === '' || $state === null || !$state->confirmed) {
            return false;
        }
        try {
            $claims = $this->signer->verify($token);
        } catch (InvalidTokenException) {
            return false;
        }

        return $claims->subject === self::DEVICE_PREFIX . $user->identifier() && hash_equals($state->fingerprint(), (string) $claims->claim('f'));
    }

    /**
     * A state is stored, but this key cannot open it: the key changed, or the state was damaged.
     */
    private function unreadable(UserInterface $user): bool
    {
        $sealed = $this->users->twoFactorStateFor($user);

        return $sealed !== null && Internal\State::open($this->box, $sealed) === null;
    }

    private function state(UserInterface $user): ?Internal\State
    {
        return Internal\State::open($this->box, $this->users->twoFactorStateFor($user));
    }

    private function save(UserInterface $user, Internal\State $state): void
    {
        $this->users->saveTwoFactorState($user, $state->seal($this->box));
    }

    private function recoveryHash(string $code): string
    {
        return $this->box->mac(strtolower((string) preg_replace('/[^a-z0-9]/i', '', $code)));
    }

    /**
     * @return list<string> Codes like "k7m2-x9qd-4tpw"
     */
    private static function newRecoveryCodes(): array
    {
        $alphabet = 'abcdefghjkmnpqrstuvwxyz23456789';
        $codes = [];
        for ($i = 0; $i < self::RECOVERY_CODES; $i++) {
            $code = '';
            for ($c = 0; $c < 12; $c++) {
                $code .= $alphabet[random_int(0, strlen($alphabet) - 1)] . ($c % 4 === 3 && $c < 11 ? '-' : '');
            }
            $codes[] = $code;
        }

        return $codes;
    }
}
