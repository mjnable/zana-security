<?php

declare(strict_types=1);

namespace Zana\Security\RateLimit;

final readonly class RateLimitResult
{
    public function __construct(
        public bool $allowed,
        public int $limit,
        public int $remaining,
        /** Seconds until the window resets */
        public int $resetAfter,
    ) {
    }

    /**
     * The RateLimit-* response headers (IETF draft), and Retry-After when refused.
     *
     * @return array<string, string>
     */
    public function headers(): array
    {
        return [
            'RateLimit-Limit' => (string) $this->limit,
            'RateLimit-Remaining' => (string) $this->remaining,
            'RateLimit-Reset' => (string) $this->resetAfter,
        ];
    }
}
