<?php

declare(strict_types=1);

namespace Zana\Security\Middleware;

use Psr\EventDispatcher\EventDispatcherInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Log\LoggerInterface;
use Zana\Http\Exception\ForbiddenHttpException;
use Zana\Security\Attribute\VerifyHuman;
use Zana\Security\Bot\BotClaimsInterface;
use Zana\Security\Bot\BotVerdict;
use Zana\Security\Bot\BotVerifierInterface;
use Zana\Security\Event\BotVerificationFailed;
use Zana\Security\Internal\HandlerReflection;
use Zana\Security\SecurityException;

/**
 * Enforces #[VerifyHuman] on the matched handler (2.25, FE-64), so it runs
 * as route middleware. A POST, PUT, PATCH or DELETE must carry the
 * verifier's token, in its form field or the X-Bot-Token header, and the
 * provider must accept it before the handler runs. Refused with 403 when:
 *
 * - there is no token, or the provider says it is not a person's;
 * - the score is below minimumScore (a provider that scores);
 * - the token was issued for another action, or, with security.bot.hostnames,
 *   on another site; or, since 2.25.1, the provider names no action or site
 *   where it reports them (BotClaimsInterface; a verifier that does not say
 *   is held to both);
 * - the provider cannot be reached, unless security.bot.on_unavailable is
 *   "allow", which lets the request through and logs it;
 * - the application is misconfigured (BotVerdict::misconfigured(), or a
 *   verifier that throws): always, whatever security.bot.on_unavailable says.
 *
 * Each refusal is logged by kind (misconfigured: error; unreachable: warning;
 * not a person: notice) and dispatches BotVerificationFailed; neither ever
 * holds the token, nor a verifier exception's message.
 */
final readonly class BotVerificationMiddleware implements MiddlewareInterface
{
    public const string HEADER = 'X-Bot-Token';

    private const string MISCONFIGURED = 'misconfigured';

    private const string UNREACHABLE = 'unreachable';

    private const string NOT_A_PERSON = 'not_a_person';

    private const array CHECKED = ['POST', 'PUT', 'PATCH', 'DELETE'];

    /**
     * @param list<string> $hostnames The sites tokens may come from; any when empty
     * @param 'refuse'|'allow' $onUnavailable
     */
    public function __construct(
        private ?BotVerifierInterface $verifier,
        private array $hostnames = [],
        private string $onUnavailable = 'refuse',
        private ?EventDispatcherInterface $events = null,
        private ?LoggerInterface $logger = null,
    ) {
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $rule = HandlerReflection::firstAttribute($request->getAttribute('_handler'), VerifyHuman::class);
        if ($rule === null || !in_array(strtoupper($request->getMethod()), self::CHECKED, true)) {
            return $handler->handle($request);
        }
        if ($this->verifier === null) {
            throw new SecurityException('#[VerifyHuman] needs a bot verifier: register a ' . BotVerifierInterface::class . ', such as mj-zana/captcha\'s.');
        }

        $body = $request->getParsedBody();
        $token = is_array($body) ? ($body[$this->verifier->field()] ?? null) : null;
        if (!is_string($token) || $token === '') {
            $token = $request->getHeaderLine(self::HEADER);
        }
        $ip = $request->getAttribute('client_ip') ?? $request->getServerParams()['REMOTE_ADDR'] ?? null;
        $ip = is_string($ip) && $ip !== '' ? $ip : null;

        if ($token === '') {
            return $this->refuse($request, $rule, self::NOT_A_PERSON, ['missing-token'], null, $ip);
        }
        if (strlen($token) > 4096) {   // providers' tokens are about 2 KB: never sent on
            return $this->refuse($request, $rule, self::NOT_A_PERSON, ['oversized-token'], null, $ip);
        }
        try {
            $verdict = $this->verifier->verify($token, $ip, $rule->action);
        } catch (\Throwable $e) {
            // A verifier must not throw: a provider out of reach is BotVerdict::unavailable(). One that does has a bug or
            // a missing class, so it is a misconfiguration (2.25.1). Its message is never logged: a custom verifier may
            // have put the token in it. Only its class is.
            $verdict = BotVerdict::misconfigured('verifier-error.' . $e::class);
        }

        if ($verdict->misconfigured) {
            // Always refused, whatever security.bot.on_unavailable says: "allow" rides out an outage, it must not hide a
            // missing secret, an unregistered HTTP client or an unset provider (2.25.1).
            return $this->refuse($request, $rule, self::MISCONFIGURED, ['misconfigured', ...self::codes($verdict->errors)], null, $ip);
        }
        if ($verdict->unavailable) {
            if ($this->onUnavailable === 'allow') {
                $this->logger?->warning('The bot verifier could not reach its provider; the request is let through (security.bot.on_unavailable).', self::context($request, $rule, ['unavailable', ...self::codes($verdict->errors)], null));

                return $handler->handle($request);
            }

            return $this->refuse($request, $rule, self::UNREACHABLE, ['unavailable', ...self::codes($verdict->errors)], null, $ip);
        }
        if (!$verdict->human) {
            return $this->refuse($request, $rule, self::NOT_A_PERSON, self::codes($verdict->errors) ?: ['not-human'], $verdict->score, $ip);
        }
        if ($rule->minimumScore !== null && $verdict->score !== null && $verdict->score < $rule->minimumScore) {
            return $this->refuse($request, $rule, self::NOT_A_PERSON, ['low-score'], $verdict->score, $ip);
        }
        if ($rule->action !== null) {
            if ($verdict->action === null && $this->reports('action')) {
                return $this->refuse($request, $rule, self::NOT_A_PERSON, ['action-missing'], $verdict->score, $ip);
            }
            if ($verdict->action !== null && $verdict->action !== $rule->action) {
                return $this->refuse($request, $rule, self::NOT_A_PERSON, ['action-mismatch'], $verdict->score, $ip);
            }
        }
        if ($this->hostnames !== []) {
            if ($verdict->hostname === null && $this->reports('hostname')) {
                return $this->refuse($request, $rule, self::NOT_A_PERSON, ['hostname-missing'], $verdict->score, $ip);
            }
            if ($verdict->hostname !== null && !in_array(strtolower($verdict->hostname), $this->hostnames, true)) {
                return $this->refuse($request, $rule, self::NOT_A_PERSON, ['hostname-mismatch'], $verdict->score, $ip);
            }
        }

        return $handler->handle($request);
    }

    /**
     * Whether the verifier's provider names the action or the hostname, so its
     * absence is refused (2.25.1). A verifier that does not say is held to both.
     *
     * @param 'action'|'hostname' $claim
     */
    private function reports(string $claim): bool
    {
        if (!$this->verifier instanceof BotClaimsInterface) {
            return true;
        }

        return $claim === 'action' ? $this->verifier->reportsAction() : $this->verifier->reportsHostname();
    }

    /**
     * Refuses, logs which kind of failure it was, and dispatches the event.
     * The three kinds have their own message and level (2.25.1): the
     * application misconfigured (error), the provider out of reach (warning),
     * the provider's or Zana's answer that this is no person (notice).
     *
     * @param self::MISCONFIGURED|self::UNREACHABLE|self::NOT_A_PERSON $kind
     * @param list<string> $reasons
     */
    private function refuse(ServerRequestInterface $request, VerifyHuman $rule, string $kind, array $reasons, ?float $score, ?string $ip): never
    {
        $context = self::context($request, $rule, $reasons, $score);
        match ($kind) {
            self::MISCONFIGURED => $this->logger?->error('The bot verifier is misconfigured, so no token can be verified; the request is refused.', $context),
            self::UNREACHABLE => $this->logger?->warning('The bot verifier could not reach its provider; the request is refused.', $context),
            self::NOT_A_PERSON => $this->logger?->notice('A request was refused: its token did not prove a person.', $context),
        };
        $this->events?->dispatch(new BotVerificationFailed($request->getUri()->getPath(), $rule->action, $reasons, $score, $ip ?? ''));

        throw new ForbiddenHttpException('Please confirm that you are a person, then send the form again.');
    }

    /**
     * What the log may hold: the path, the action, the reasons and the score;
     * never the token, nor an exception's message.
     *
     * @param list<string> $reasons
     * @return array{kind: string, path: string, action: string|null, reasons: list<string>, score: float|null}
     */
    private static function context(ServerRequestInterface $request, VerifyHuman $rule, array $reasons, ?float $score): array
    {
        return ['kind' => 'bot_verification', 'path' => $request->getUri()->getPath(), 'action' => $rule->action, 'reasons' => $reasons, 'score' => $score];
    }

    /**
     * The provider's codes, kept only when they read as codes: they come from
     * outside, and go to the audit log.
     *
     * @param list<string> $errors
     * @return list<string>
     */
    private static function codes(array $errors): array
    {
        return array_map(
            static fn (string $code): string => preg_match('/^[A-Za-z0-9_.\\\\-]{1,80}$/', $code) === 1 ? $code : 'unreadable-code',
            array_slice($errors, 0, 10),
        );
    }
}
