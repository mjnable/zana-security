<?php

declare(strict_types=1);

namespace Zana\Security\Internal;

use Zana\Security\SecurityException;

/**
 * Encrypts second-factor state with libsodium (XSalsa20-Poly1305) under
 * security.two_factor.key, which is separate from security.secret so that
 * rotating the token secret does not lock users out of their second factor.
 * Also keys the HMAC of recovery codes.
 *
 * @internal
 */
final readonly class SecretBox
{
    public const int MINIMUM_KEY_LENGTH = 32;

    private const string PREFIX = 'v1:';

    private string $key;

    public function __construct(#[\SensitiveParameter] string $key)
    {
        if (strlen($key) < self::MINIMUM_KEY_LENGTH) {
            throw new SecurityException('security.two_factor.key must be at least ' . self::MINIMUM_KEY_LENGTH . ' characters; generate one with: php -r "echo bin2hex(random_bytes(32));"');
        }
        $this->key = sodium_crypto_generichash($key, '', SODIUM_CRYPTO_SECRETBOX_KEYBYTES);
    }

    public function seal(string $plain): string
    {
        $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);

        return self::PREFIX . sodium_bin2base64($nonce . sodium_crypto_secretbox($plain, $nonce, $this->key), SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
    }

    /**
     * The plain text, or null when the box was tampered with or sealed under another key.
     */
    public function open(string $sealed): ?string
    {
        if (!str_starts_with($sealed, self::PREFIX)) {
            return null;
        }
        try {
            $raw = sodium_base642bin(substr($sealed, strlen(self::PREFIX)), SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
        } catch (\SodiumException) {
            return null;
        }
        if (strlen($raw) <= SODIUM_CRYPTO_SECRETBOX_NONCEBYTES) {
            return null;
        }
        $plain = sodium_crypto_secretbox_open(substr($raw, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES), substr($raw, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES), $this->key);

        return $plain === false ? null : $plain;
    }

    public function mac(string $value): string
    {
        return hash_hmac('sha256', $value, $this->key);
    }
}
