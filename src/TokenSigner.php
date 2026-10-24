<?php

declare(strict_types=1);

namespace Zana\Security;

use Closure;

/**
 * Issues and verifies signed bearer tokens:
 *
 *     base64url(JSON {sub, iat, exp, claims}) . "." . base64url(HMAC-SHA256)
 *
 * The payload is signed, not encrypted: do not put secrets in claims.
 */
final class TokenSigner
{
    public const int MIN_SECRET_LENGTH = 32;

    /** @var Closure(): int */
    private readonly Closure $now;

    /**
     * @param (Closure(): int)|null $clock Returns the current Unix time; defaults to time()
     */
    public function __construct(
        #[\SensitiveParameter] private readonly string $secret,
        ?Closure $clock = null,
    ) {
        if (strlen($secret) < self::MIN_SECRET_LENGTH) {
            throw new SecurityException('The token secret must be at least ' . self::MIN_SECRET_LENGTH . ' bytes long.');
        }
        $this->now = $clock ?? static fn (): int => time();
    }

    /**
     * @param array<string, mixed> $claims Must be JSON-encodable
     */
    public function issue(string $subject, int $ttlSeconds, array $claims = []): string
    {
        if ($subject === '') {
            throw new SecurityException('A token needs a subject.');
        }
        if ($ttlSeconds < 1) {
            throw new SecurityException("A token's lifetime must be positive; got {$ttlSeconds}.");
        }

        $now = ($this->now)();
        try {
            $payload = self::encode(json_encode(['sub' => $subject, 'iat' => $now, 'exp' => $now + $ttlSeconds, 'claims' => (object) $claims], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES));
        } catch (\JsonException $e) {
            throw new SecurityException('Token claims must be JSON-encodable: ' . $e->getMessage(), previous: $e);
        }

        return $payload . '.' . $this->sign($payload);
    }

    public function verify(string $token): TokenClaims
    {
        $parts = explode('.', $token);
        if (count($parts) !== 2 || $parts[0] === '' || $parts[1] === '') {
            throw new InvalidTokenException(InvalidTokenException::MALFORMED, 'The token is malformed.');
        }
        [$payload, $signature] = $parts;

        if (!hash_equals($this->sign($payload), $signature)) {
            throw new InvalidTokenException(InvalidTokenException::SIGNATURE, 'The token signature is invalid.');
        }

        $data = json_decode((string) self::decode($payload), true);
        if (
            !is_array($data)
            || !is_string($data['sub'] ?? null) || $data['sub'] === ''
            || !is_int($data['iat'] ?? null) || !is_int($data['exp'] ?? null)
            || !is_array($data['claims'] ?? null)
        ) {
            throw new InvalidTokenException(InvalidTokenException::MALFORMED, 'The token payload is malformed.');
        }

        if (($this->now)() >= $data['exp']) {
            throw new InvalidTokenException(InvalidTokenException::EXPIRED, 'The token has expired.');
        }

        /** @var array<string, mixed> $claims */
        $claims = $data['claims'];

        return new TokenClaims($data['sub'], new \DateTimeImmutable('@' . $data['iat']), new \DateTimeImmutable('@' . $data['exp']), $claims);
    }

    private function sign(string $payload): string
    {
        return self::encode(hash_hmac('sha256', $payload, $this->secret, true));
    }

    private static function encode(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    private static function decode(string $text): string|false
    {
        return base64_decode(strtr($text, '-_', '+/'), true);
    }
}
