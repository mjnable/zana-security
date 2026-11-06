<?php

declare(strict_types=1);

namespace Zana\Security\TwoFactor\Internal;

use Zana\Security\Internal\SecretBox;

/**
 * A user's second factor, sealed into the one string the user provider
 * stores: the TOTP secret, the recovery code hashes, the last step used (a
 * code works once) and whether enrolment was confirmed.
 *
 * @internal
 */
final readonly class State
{
    /**
     * @param list<string> $recoveryHashes
     */
    public function __construct(
        #[\SensitiveParameter] public string $secret,
        public array $recoveryHashes,
        public ?int $lastStep = null,
        public bool $confirmed = false,
    ) {
    }

    public static function open(SecretBox $box, ?string $sealed): ?self
    {
        $plain = $sealed === null ? null : $box->open($sealed);
        $data = $plain === null ? null : json_decode($plain, true);
        if (!is_array($data) || !is_string($data['s'] ?? null) || !is_array($data['r'] ?? null)) {
            return null;
        }

        return new self(
            $data['s'],
            array_values(array_filter($data['r'], is_string(...))),
            is_int($data['l'] ?? null) ? $data['l'] : null,
            ($data['c'] ?? false) === true,
        );
    }

    public function seal(SecretBox $box): string
    {
        return $box->seal(json_encode(['v' => 1, 's' => $this->secret, 'r' => $this->recoveryHashes, 'l' => $this->lastStep, 'c' => $this->confirmed], JSON_THROW_ON_ERROR));
    }

    /**
     * @param list<string>|null $recoveryHashes
     */
    public function with(?array $recoveryHashes = null, ?int $lastStep = null, ?bool $confirmed = null): self
    {
        return new self(
            $this->secret,
            $recoveryHashes ?? $this->recoveryHashes,
            $lastStep ?? $this->lastStep,
            $confirmed ?? $this->confirmed,
        );
    }

    /**
     * Changes when the user enrols again, so remembered devices stop working.
     */
    public function fingerprint(): string
    {
        return substr(hash('sha256', 'device:' . $this->secret), 0, 16);
    }
}
