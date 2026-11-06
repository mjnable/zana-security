<?php

declare(strict_types=1);

namespace Zana\Security\TwoFactor;

use Closure;
use Zana\Security\Internal\Base32;

/**
 * Time-based one-time passwords (RFC 6238), as authenticator apps compute
 * them: HMAC-SHA1, 6 digits, 30-second steps (FE-56, 2.16).
 */
final readonly class Totp
{
    public const int STEP = 30;

    public const int DIGITS = 6;

    /** @var Closure(): int */
    private Closure $clock;

    /**
     * @param (Closure(): int)|null $clock
     * @param int $drift Steps accepted before and after the current one
     */
    public function __construct(?Closure $clock = null, private int $drift = 1)
    {
        $this->clock = $clock ?? time(...);
    }

    /**
     * A new secret, base32-encoded (160 bits).
     */
    public function generateSecret(): string
    {
        return Base32::encode(random_bytes(20));
    }

    /**
     * The otpauth:// URI that authenticator apps read from a QR code; drawing the QR code is the application's.
     */
    public function uri(#[\SensitiveParameter] string $secret, string $issuer, string $account): string
    {
        return 'otpauth://totp/' . rawurlencode($issuer) . ':' . rawurlencode($account)
            . '?secret=' . $secret . '&issuer=' . rawurlencode($issuer) . '&algorithm=SHA1&digits=' . self::DIGITS . '&period=' . self::STEP;
    }

    public function currentStep(): int
    {
        return intdiv(($this->clock)(), self::STEP);
    }

    public function code(#[\SensitiveParameter] string $secret, ?int $step = null): string
    {
        $hash = hash_hmac('sha1', pack('J', $step ?? $this->currentStep()), Base32::decode($secret), true);
        $offset = ord($hash[19]) & 0x0f;
        $value = ((ord($hash[$offset]) & 0x7f) << 24) | (ord($hash[$offset + 1]) << 16) | (ord($hash[$offset + 2]) << 8) | ord($hash[$offset + 3]);

        return str_pad((string) ($value % 10 ** self::DIGITS), self::DIGITS, '0', STR_PAD_LEFT);
    }

    /**
     * The step the code belongs to, within the accepted drift and after $lastUsedStep (a code is used once); null otherwise.
     */
    public function verify(#[\SensitiveParameter] string $secret, string $code, ?int $lastUsedStep = null): ?int
    {
        $code = preg_replace('/\s+/', '', $code) ?? '';
        if (preg_match('/^\d{' . self::DIGITS . '}$/', $code) !== 1) {
            return null;
        }
        $now = $this->currentStep();
        for ($step = $now - $this->drift; $step <= $now + $this->drift; $step++) {
            if (($lastUsedStep === null || $step > $lastUsedStep) && hash_equals($this->code($secret, $step), $code)) {
                return $step;
            }
        }

        return null;
    }
}
