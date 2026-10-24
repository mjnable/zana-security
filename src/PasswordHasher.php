<?php

declare(strict_types=1);

namespace Zana\Security;

/**
 * Hashes passwords with Argon2id when PHP supports it, otherwise bcrypt.
 * Passwords longer than 4,096 bytes are rejected, to keep hashing cheap to
 * refuse.
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

        return password_hash($plain, $this->algorithm, $this->options);
    }

    public function verify(string $plain, string $hash): bool
    {
        return strlen($plain) <= self::MAX_LENGTH && password_verify($plain, $hash);
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

    private function guard(string $plain): void
    {
        if (strlen($plain) > self::MAX_LENGTH) {
            throw new SecurityException('Passwords cannot be longer than ' . self::MAX_LENGTH . ' bytes.');
        }
    }
}
