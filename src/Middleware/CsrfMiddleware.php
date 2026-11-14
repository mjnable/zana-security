<?php

declare(strict_types=1);

namespace Zana\Security\Middleware;

use Nyholm\Psr7\Response;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Zana\Http\Exception\ForbiddenHttpException;
use Zana\Security\Attribute\WithoutCsrf;
use Zana\Security\CsrfTokens;
use Zana\Security\Internal\HandlerReflection;

/**
 * Refuses POST, PUT, PATCH and DELETE requests that may come from another
 * site:
 *
 * 1. Sec-Fetch-Site, when the browser sends it, must be same-origin or none;
 * 2. Origin, when sent, must match the request's host, and its port when it
 *    names one (2.20, S16): browsers leave a default port out, so a site
 *    behind a proxy that does not pass the port on is not refused;
 * 3. the token from the "_token" field or the X-CSRF-Token header must be
 *    valid for the form named by the "_form" field ("default" otherwise).
 *
 * Requests with a valid bearer token are not checked: token-authenticated
 * APIs are not exposed to CSRF. Any other Authorization header is checked
 * like a request without one (2.19.1). Handlers marked #[WithoutCsrf] are skipped
 * when the middleware runs as route middleware.
 *
 * Anti-spam (FE-22): a filled honeypot field, or a form posted sooner than
 * the tokens' minimum age, is treated as a bot. With $spamRedirect the bot
 * gets a 303 to that path, as if it had succeeded; otherwise a 403.
 */
final readonly class CsrfMiddleware implements MiddlewareInterface
{
    private const array UNSAFE_METHODS = ['POST', 'PUT', 'PATCH', 'DELETE'];

    public function __construct(
        private CsrfTokens $tokens,
        private ?string $spamRedirect = null,
    ) {
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        if (!in_array(strtoupper($request->getMethod()), self::UNSAFE_METHODS, true)
            || $this->hasBearerToken($request)
            || HandlerReflection::has($request->getAttribute('_handler'), WithoutCsrf::class)
        ) {
            return $handler->handle($request);
        }

        $site = strtolower($request->getHeaderLine('Sec-Fetch-Site'));
        if ($site !== '' && $site !== 'same-origin' && $site !== 'none') {
            throw new ForbiddenHttpException('Cross-site form submissions are not accepted.');
        }

        $origin = $request->getHeaderLine('Origin');
        if ($origin !== '' && $origin !== 'null' && !self::sameOrigin($origin, $request)) {
            throw new ForbiddenHttpException('Cross-site form submissions are not accepted.');
        }

        $body = $request->getParsedBody();
        $fields = is_array($body) ? $body : [];
        $token = $fields[CsrfTokens::FIELD] ?? $request->getHeaderLine(CsrfTokens::HEADER);
        $form = $fields[CsrfTokens::FORM_FIELD] ?? CsrfTokens::DEFAULT_FORM;

        if (!is_string($token) || $token === '' || !is_string($form) || !$this->tokens->verify($token, $form)) {
            throw new ForbiddenHttpException('The form has expired or is invalid. Reload the page and try again.');
        }

        $honeypot = $this->tokens->honeypot;
        $trapped = $honeypot !== null && is_string($fields[$honeypot] ?? null) && trim($fields[$honeypot]) !== '';
        if ($trapped || $this->tokens->isTooFresh($token)) {
            if ($this->spamRedirect !== null) {
                return new Response(303, ['Location' => $this->spamRedirect]);
            }
            throw new ForbiddenHttpException('The form could not be accepted.');
        }

        return $handler->handle($request);
    }

    /**
     * The Origin's host is the request's, and so is its port when it names one: https://site.example:8443 is another
     * service on the same machine. The request's port is the one TrustedProxiesMiddleware found, or the URI's.
     */
    private static function sameOrigin(string $origin, ServerRequestInterface $request): bool
    {
        $uri = $request->getUri();
        if (strtolower((string) parse_url($origin, PHP_URL_HOST)) !== strtolower($uri->getHost())) {
            return false;
        }
        $port = parse_url($origin, PHP_URL_PORT);
        if (!is_int($port)) {
            return true;
        }

        return $port === ($uri->getPort() ?? ($uri->getScheme() === 'https' ? 443 : 80));
    }

    private function hasBearerToken(ServerRequestInterface $request): bool
    {
        return preg_match('/^Bearer\s+(\S+)$/i', trim($request->getHeaderLine('Authorization')), $match) === 1 && $this->tokens->isBearerToken($match[1]);
    }
}
