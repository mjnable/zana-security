<?php

declare(strict_types=1);

namespace Zana\Security\Bot;

/**
 * What a bot verifier's provider says about a token besides yes or no
 * (2.25.1), so expectations are enforced strictly where they can be:
 *
 * - an action in #[VerifyHuman(action: …)] must come back when the provider
 *   reports actions, or the request is refused;
 * - with security.bot.hostnames, a hostname must come back when the provider
 *   reports hostnames, or the request is refused.
 *
 * Optional: a verifier that does not implement it is held to both, and
 * `check` warns where a provider cannot report what is expected.
 *
 * @api
 */
interface BotClaimsInterface
{
    public function reportsAction(): bool;

    public function reportsHostname(): bool;
}
