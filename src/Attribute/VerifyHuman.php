<?php

declare(strict_types=1);

namespace Zana\Security\Attribute;

use Attribute;

/**
 * Asks the bot verifier (a CAPTCHA provider) about the token sent with the
 * request before the handler runs (2.25, FE-64), enforced by
 * BotVerificationMiddleware on the route:
 *
 *     #[VerifyHuman(action: 'checkout', minimumScore: 0.5)]
 *
 * @param string|null $action Named in the token by the widget (Turnstile, reCAPTCHA v3); a token for another action is refused
 * @param float|null $minimumScore With a provider that scores (reCAPTCHA v3): a lower score is refused
 */
#[Attribute(Attribute::TARGET_CLASS | Attribute::TARGET_METHOD | Attribute::TARGET_FUNCTION)]
final readonly class VerifyHuman
{
    public function __construct(
        public ?string $action = null,
        public ?float $minimumScore = null,
    ) {
    }
}
