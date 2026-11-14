<?php

declare(strict_types=1);

namespace Zana\Security\Bot;

/**
 * Verifies a CAPTCHA token with its provider (2.25, FE-64): Cloudflare
 * Turnstile, Google reCAPTCHA or hCaptcha, from mj-zana/captcha, or the
 * application's own. Security holds no provider code.
 *
 * @api
 */
interface BotVerifierInterface
{
    /**
     * The form field the provider's widget fills with its token, such as
     * "cf-turnstile-response".
     */
    public function field(): string;

    /**
     * Whether the provider gives a score (reCAPTCHA v3), which
     * #[VerifyHuman(minimumScore: …)] needs.
     */
    public function scores(): bool;

    /**
     * Asks the provider about a token. A provider that cannot be reached
     * gives BotVerdict::unavailable(), never an exception.
     */
    public function verify(string $token, ?string $clientIp = null, ?string $action = null): BotVerdict;
}
