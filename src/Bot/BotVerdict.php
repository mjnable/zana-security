<?php

declare(strict_types=1);

namespace Zana\Security\Bot;

/**
 * A bot verifier's answer about one token (2.25, FE-64).
 *
 * @api
 */
final readonly class BotVerdict
{
    /**
     * @param bool $human The provider accepted the token
     * @param float|null $score From 0.0 (a bot) to 1.0 (a person), when the provider scores (reCAPTCHA v3)
     * @param list<string> $errors The provider's error codes, such as "timeout-or-duplicate"
     * @param string|null $action The action the token was issued for, when the provider says
     * @param string|null $hostname The site the token was issued on, when the provider says
     * @param bool $unavailable The provider could not be asked or did not answer clearly: neither human nor bot
     * @param bool $misconfigured The application, not the provider, is wrong (2.25.1): a missing or wrong secret, no
     *                            HTTP client, no provider. Always refused, whatever security.bot.on_unavailable says
     */
    public function __construct(
        public bool $human,
        public ?float $score = null,
        public array $errors = [],
        public ?string $action = null,
        public ?string $hostname = null,
        public bool $unavailable = false,
        public bool $misconfigured = false,
    ) {
    }

    public static function human(?float $score = null, ?string $action = null, ?string $hostname = null): self
    {
        return new self(true, $score, [], $action, $hostname);
    }

    /**
     * @param list<string> $errors
     */
    public static function bot(array $errors = [], ?float $score = null): self
    {
        return new self(false, $score, $errors);
    }

    /**
     * The provider could not be reached, or its answer could not be read.
     */
    public static function unavailable(string $why): self
    {
        return new self(false, null, [$why], unavailable: true);
    }

    /**
     * The application is set up so that no token can be verified (2.25.1):
     * refused always, so that letting requests through while a provider is
     * down never hides missing credentials or a missing HTTP client.
     */
    public static function misconfigured(string $why): self
    {
        return new self(false, null, [$why], unavailable: true, misconfigured: true);
    }
}
