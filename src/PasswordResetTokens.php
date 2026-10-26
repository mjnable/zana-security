<?php

declare(strict_types=1);

namespace Zana\Security;

use Psr\SimpleCache\CacheInterface;

/**
 * Password reset links (FE-28): a signed token, sent by email, that works
 * once, expires, and stops working as soon as the password changes.
 *
 *     $link = $urls->generate('password.reset', ['token' => $resets->issue($user)]);
 *     …
 *     $user = $resets->consume($token) ?? throw new NotFoundHttpException();
 */
final readonly class PasswordResetTokens
{
    private const string SUBJECT_PREFIX = 'reset:';

    public function __construct(
        private TokenSigner $signer,
        private CacheInterface $cache,
        private PasswordUserProviderInterface $users,
        private int $lifetime = 3600,
    ) {
    }

    public function issue(UserInterface $user): string
    {
        return $this->signer->issue(self::SUBJECT_PREFIX . $user->identifier(), $this->lifetime, [
            'nonce' => bin2hex(random_bytes(16)),
            'password' => $this->fingerprint($user),
        ]);
    }

    /**
     * The user of a valid token, which is then used up; null otherwise.
     */
    public function consume(string $token): ?UserInterface
    {
        $user = $this->check($token);
        if ($user === null) {
            return null;
        }
        $nonce = $this->signer->verify($token)->claim('nonce');
        $this->cache->set('zana.reset.' . hash('xxh128', (string) $nonce), true, $this->lifetime);

        return $user;
    }

    /**
     * The user of a valid token, without using it up: to show the reset form.
     */
    public function check(string $token): ?UserInterface
    {
        try {
            $claims = $this->signer->verify($token);
        } catch (InvalidTokenException) {
            return null;
        }

        $nonce = $claims->claim('nonce');
        if (!str_starts_with($claims->subject, self::SUBJECT_PREFIX) || !is_string($nonce) || $this->cache->has('zana.reset.' . hash('xxh128', $nonce))) {
            return null;
        }

        $user = $this->users->findByIdentifier(substr($claims->subject, strlen(self::SUBJECT_PREFIX)));
        if ($user === null || !hash_equals($this->fingerprint($user), (string) $claims->claim('password'))) {
            return null;
        }

        return $user;
    }

    private function fingerprint(UserInterface $user): string
    {
        return substr(hash('sha256', (string) $this->users->passwordHashFor($user)), 0, 16);
    }
}
