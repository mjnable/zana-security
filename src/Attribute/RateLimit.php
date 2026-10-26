<?php

declare(strict_types=1);

namespace Zana\Security\Attribute;

use Attribute;

/**
 * Limits how often a client may call a handler; enforced by
 * RateLimitMiddleware as route middleware:
 *
 *     #[RateLimit(max: 5, per: 3600)]   // five contact messages per visitor per hour
 */
#[Attribute(Attribute::TARGET_CLASS | Attribute::TARGET_METHOD | Attribute::TARGET_FUNCTION)]
final readonly class RateLimit
{
    /**
     * @param 'ip'|'user'|'global' $by Whose attempts are counted: the client address, the signed-in user (else the address), or everyone together
     * @param 'fixed'|'sliding' $strategy
     * @param string|null $name Shares one counter between handlers; defaults to the handler
     */
    public function __construct(
        public int $max,
        public int $per = 60,
        public string $by = 'ip',
        public string $strategy = 'sliding',
        public ?string $name = null,
    ) {
    }
}
