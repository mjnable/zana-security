<?php

declare(strict_types=1);

namespace Zana\Security;

/**
 * The verified contents of a token.
 */
final readonly class TokenClaims
{
    /**
     * @param array<string, mixed> $claims
     */
    public function __construct(
        public string $subject,
        public \DateTimeImmutable $issuedAt,
        public \DateTimeImmutable $expiresAt,
        public array $claims = [],
    ) {
    }

    public function claim(string $name, mixed $default = null): mixed
    {
        return array_key_exists($name, $this->claims) ? $this->claims[$name] : $default;
    }
}
