<?php

declare(strict_types=1);

namespace Zana\Security\Session;

use Nyholm\Psr7\Response;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Zana\Http\BasePath;
use Zana\Http\Exception\UnauthorizedHttpException;
use Zana\Security\Middleware\AuthenticationMiddleware;
use Zana\Security\PasswordUserProviderInterface;
use Zana\Security\SecurityContext;
use Zana\Security\UserProviderInterface;
use Zana\Session\SessionContext;

/**
 * Authenticates the user signed in by SessionLogin, for every request that
 * runs after SessionMiddleware. #[RequiresAuthentication] and
 * #[RequiresPermission] then work unchanged.
 *
 * An HTML request that needs a user and has none is redirected to the login
 * page (security.login.path) with ?to=<the requested path>; JSON requests
 * still get 401.
 *
 * With the password user provider, a session from before a password change
 * is signed out, and so is one that remembers no password (2.19.1).
 */
final readonly class SessionAuthenticationMiddleware implements MiddlewareInterface
{
    public function __construct(
        private SessionContext $sessions,
        private UserProviderInterface $users,
        private SecurityContext $context,
        private ?string $loginPath = null,
        private ?PasswordUserProviderInterface $passwords = null,
    ) {
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $session = $this->sessions->session();
        $id = $session->get(SessionLogin::SESSION_KEY);
        if (is_string($id)) {
            $user = $this->users->findByIdentifier($id);
            $passwords = $this->passwords ?? ($this->users instanceof PasswordUserProviderInterface ? $this->users : null);
            if ($user !== null && $passwords !== null && !hash_equals(SessionLogin::passwordFingerprint($passwords->passwordHashFor($user)), (string) $session->get(SessionLogin::PASSWORD_KEY, ''))) {
                $user = null;   // the password changed since this session signed in
            }
            if ($user === null) {
                $session->remove(SessionLogin::SESSION_KEY);   // the account is gone, or its password changed
                $session->remove(SessionLogin::PASSWORD_KEY);
            } else {
                $this->context->setUser($user);
                $request = $request->withAttribute(AuthenticationMiddleware::ATTRIBUTE, $user);
            }
        }

        try {
            return $handler->handle($request);
        } catch (UnauthorizedHttpException $e) {
            if ($this->loginPath === null || self::wantsJson($request)) {
                throw $e;
            }
            $base = $request->getAttribute(BasePath::ATTRIBUTE, '');
            $base = is_string($base) ? $base : '';
            $to = $base . $request->getUri()->getPath() . ($request->getUri()->getQuery() !== '' ? '?' . $request->getUri()->getQuery() : '');

            return new Response(303, ['Location' => $base . $this->loginPath . '?' . http_build_query(['to' => $to])]);
        }
    }

    private static function wantsJson(ServerRequestInterface $request): bool
    {
        return str_contains(strtolower($request->getHeaderLine('Accept')), 'json');
    }
}
