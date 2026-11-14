<?php

declare(strict_types=1);

namespace Zana\Security\Middleware;

use Nyholm\Psr7\Response;
use Psr\EventDispatcher\EventDispatcherInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Zana\Http\Exception\ForbiddenHttpException;
use Zana\Security\Attribute\SpamRules;
use Zana\Security\Event\SpamRefused;
use Zana\Security\Internal\HandlerReflection;
use Zana\Security\SecurityContext;
use Zana\Security\Spam\SpamGuard;
use Zana\Security\Spam\Submission;

/**
 * Enforces #[SpamRules('form')] on the matched handler (2.24, FE-63), so it
 * runs as route middleware. A POST, PUT or PATCH whose text the form's rules
 * call spam is treated as a filled honeypot: sent to the form's redirect, or
 * security.csrf.spam_redirect, with 303, as if it had succeeded; otherwise
 * refused with 403, in the same words, so a bot cannot tell which check
 * stopped it. Each refusal dispatches SpamRefused.
 *
 * What is accepted is remembered (for duplicate_minutes) only when the
 * handler answers without an error, so a person who corrects the form and
 * sends the same message again is not refused.
 */
final readonly class SpamGuardMiddleware implements MiddlewareInterface
{
    private const array CHECKED = ['POST', 'PUT', 'PATCH'];

    public function __construct(
        private SpamGuard $guard,
        private ?string $honeypot = null,
        private ?string $spamRedirect = null,
        private ?SecurityContext $security = null,
        private ?EventDispatcherInterface $events = null,
    ) {
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $rules = HandlerReflection::firstAttribute($request->getAttribute('_handler'), SpamRules::class);
        if ($rules === null || !in_array(strtoupper($request->getMethod()), self::CHECKED, true)) {
            return $handler->handle($request);
        }

        $profile = $this->guard->profile($rules->form);
        $submission = Submission::fromRequest($request, $rules->form, $profile->fields, $this->honeypot, $this->security?->user()?->identifier());
        $verdict = $this->guard->judge($rules->form, $submission);
        if ($verdict->spam) {
            $ip = $request->getAttribute('client_ip') ?? $request->getServerParams()['REMOTE_ADDR'] ?? '';
            $this->events?->dispatch(new SpamRefused($rules->form, $verdict->reasons(), $verdict->points, is_string($ip) ? $ip : ''));
            $redirect = $profile->redirect ?? $this->spamRedirect;
            if ($redirect !== null) {
                return new Response(303, ['Location' => $redirect]);
            }
            throw new ForbiddenHttpException('The form could not be accepted.');
        }

        $response = $handler->handle($request);
        if ($response->getStatusCode() < 400) {
            $this->guard->accepted($rules->form, $submission);
        }

        return $response;
    }
}
