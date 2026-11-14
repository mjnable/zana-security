<?php

declare(strict_types=1);

namespace Zana\Security\Bot;

/**
 * Accepts every token, without asking anyone (2.25, FE-64): for development
 * before a provider is chosen. It verifies nothing, so `check` reports it as
 * an error in production when a route relies on it.
 */
final readonly class NullBotVerifier implements BotVerifierInterface, BotClaimsInterface
{
    /** It answers with the action asked for. */
    public function reportsAction(): bool
    {
        return true;
    }

    public function reportsHostname(): bool
    {
        return false;
    }

    public function field(): string
    {
        return 'bot_token';
    }

    public function scores(): bool
    {
        return false;
    }

    public function verify(string $token, ?string $clientIp = null, ?string $action = null): BotVerdict
    {
        return BotVerdict::human(action: $action);
    }
}
