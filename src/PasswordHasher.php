<?php

declare(strict_types=1);

namespace Zana\Security;

/**
 * Hashes passwords with Argon2id when PHP supports it, otherwise bcrypt.
 * Passwords longer than 4,096 bytes are rejected, to keep hashing cheap to
 * refuse.
 *
 * bcrypt reads only the first 72 bytes and stops at a NUL byte, so such
 * passwords are pre-hashed with SHA-384 for bcrypt; every byte counts.
 */
final class PasswordHasher
{
    public const int MAX_LENGTH = 4096;

    private readonly string $algorithm;

    /**
     * @param array<string, int> $options password_hash() options, e.g. ['memory_cost' => 65536] or ['cost' => 12]
     */
    public function __construct(
        private readonly array $options = [],
        ?string $algorithm = null,
    ) {
        $this->algorithm = $algorithm ?? (defined('PASSWORD_ARGON2ID') ? PASSWORD_ARGON2ID : PASSWORD_BCRYPT);
    }

    public function hash(string $plain): string
    {
        $this->guard($plain);
        $bcrypt = $this->algorithm === PASSWORD_BCRYPT;

        return password_hash($bcrypt ? self::forBcrypt($plain) : $plain, $this->algorithm, $this->options);
    }

    public function verify(string $plain, string $hash): bool
    {
        if (strlen($plain) > self::MAX_LENGTH) {
            return false;
        }

        $bcrypt = password_get_info($hash)['algo'] === PASSWORD_BCRYPT;

        return password_verify($bcrypt ? self::forBcrypt($plain) : $plain, $hash);
    }

    /**
     * Whether $hash was made with another algorithm or other options; rehash
     * the password after a successful verify() when it was.
     */
    public function needsRehash(string $hash): bool
    {
        return password_needs_rehash($hash, $this->algorithm, $this->options);
    }

    public function algorithm(): string
    {
        return $this->algorithm;
    }

    private static function forBcrypt(string $plain): string
    {
        if (strlen($plain) <= 72 && !str_contains($plain, "\0")) {
            return $plain;
        }

        // 64 base64 characters: within bcrypt's 72 bytes, and never a NUL
        return base64_encode(hash('sha384', $plain, true));
    }

    private function guard(string $plain): void
    {
        if (strlen($plain) > self::MAX_LENGTH) {
            throw new SecurityException('Passwords cannot be longer than ' . self::MAX_LENGTH . ' bytes.');
        }
    }
}
