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
 *   on another site;
 * - the provider cannot be reached, unless security.bot.on_unavailable is
 *   "allow", which lets the request through and logs it.
 *
 * Each refusal dispatches BotVerificationFailed, never with the token.
 */
final readonly class BotVerificationMiddleware implements MiddlewareInterface
{
    public const string HEADER = 'X-Bot-Token';

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
            return $this->refuse($request, $rule, ['missing-token'], null, $ip);
        }
        if (strlen($token) > 4096) {   // providers' tokens are about 2 KB: never sent on
            return $this->refuse($request, $rule, ['oversized-token'], null, $ip);
        }
        try {
            $verdict = $this->verifier->verify($token, $ip, $rule->action);
        } catch (\Throwable $e) {
            // A verifier must not throw; when one does, it is usually a bug or a missing class: say which, and refuse.
            $this->logger?->error('The bot verifier failed; the request is refused.', ['path' => $request->getUri()->getPath(), 'exception' => $e::class, 'message' => mb_substr($e->getMessage(), 0, 300)]);
            $verdict = BotVerdict::unavailable($e::class);
        }

        if ($verdict->unavailable) {
            $this->logger?->warning('The bot verifier could not be asked about a token.', ['path' => $request->getUri()->getPath(), 'reasons' => self::codes($verdict->errors)]);
            if ($this->onUnavailable === 'allow') {
                return $handler->handle($request);
            }

            return $this->refuse($request, $rule, ['unavailable', ...self::codes($verdict->errors)], null, $ip);
        }
        if (!$verdict->human) {
            return $this->refuse($request, $rule, self::codes($verdict->errors) ?: ['not-human'], $verdict->score, $ip);
        }
        if ($rule->minimumScore !== null && $verdict->score !== null && $verdict->score < $rule->minimumScore) {
            return $this->refuse($request, $rule, ['low-score'], $verdict->score, $ip);
        }
        if ($rule->action !== null && $verdict->action !== null && $verdict->action !== $rule->action) {
            return $this->refuse($request, $rule, ['action-mismatch'], $verdict->score, $ip);
        }
        if ($this->hostnames !== [] && $verdict->hostname !== null && !in_array(strtolower($verdict->hostname), $this->hostnames, true)) {
            return $this->refuse($request, $rule, ['hostname-mismatch'], $verdict->score, $ip);
        }

        return $handler->handle($request);
    }

    /**
     * @param list<string> $reasons
     */
    private function refuse(ServerRequestInterface $request, VerifyHuman $rule, array $reasons, ?float $score, ?string $ip): never
    {
        $this->events?->dispatch(new BotVerificationFailed($request->getUri()->getPath(), $rule->action, $reasons, $score, $ip ?? ''));

        throw new ForbiddenHttpException('Please confirm that you are a person, then send the form again.');
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
