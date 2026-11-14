<?php

declare(strict_types=1);

namespace Zana\Security\Bot;

/**
 * For tests, without the network (2.25, FE-64): each known token gives its
 * verdict, any other is a bot, and every call is recorded.
 *
 *     $bots = new FakeBotVerifier(['person' => BotVerdict::human(0.9), 'down' => BotVerdict::unavailable('timeout')]);
 *     // register it as BotVerifierInterface, post the form with bot_token=person
 */
final class FakeBotVerifier implements BotVerifierInterface
{
    /** @var list<array{token: string, clientIp: string|null, action: string|null}> */
    public array $calls = [];

    /**
     * @param array<string, BotVerdict|bool> $verdicts By token; true is a person, false a bot
     */
    public function __construct(
        private readonly array $verdicts = ['human' => true],
        private readonly string $field = 'bot_token',
        private readonly bool $scores = false,
    ) {
    }

    public function field(): string
    {
        return $this->field;
    }

    public function scores(): bool
    {
        return $this->scores;
    }

    public function verify(string $token, ?string $clientIp = null, ?string $action = null): BotVerdict
    {
        $this->calls[] = ['token' => $token, 'clientIp' => $clientIp, 'action' => $action];
        $verdict = $this->verdicts[$token] ?? false;

        return match (true) {
            $verdict instanceof BotVerdict => $verdict,
            $verdict => BotVerdict::human(action: $action),
            default => BotVerdict::bot(['invalid-input-response']),
        };
    }
}
