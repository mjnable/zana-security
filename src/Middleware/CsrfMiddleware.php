<?php

declare(strict_types=1);

namespace Zana\Security\Middleware;

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
 * 2. Origin, when sent, must match the request's host;
 * 3. the token from the "_token" field or the X-CSRF-Token header must be
 *    valid for the form named by the "_form" field ("default" otherwise).
 *
 * Requests with an Authorization header are not checked: token-authenticated
 * APIs are not exposed to CSRF. Handlers marked #[WithoutCsrf] are skipped
 * when the middleware runs as route middleware.
 */
final readonly class CsrfMiddleware implements MiddlewareInterface
{
    private const array UNSAFE_METHODS = ['POST', 'PUT', 'PATCH', 'DELETE'];

    public function __construct(private CsrfTokens $tokens)
    {
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        if (!in_array(strtoupper($request->getMethod()), self::UNSAFE_METHODS, true)
            || $request->hasHeader('Authorization')
            || HandlerReflection::has($request->getAttribute('_handler'), WithoutCsrf::class)
        ) {
            return $handler->handle($request);
        }

        $site = strtolower($request->getHeaderLine('Sec-Fetch-Site'));
        if ($site !== '' && $site !== 'same-origin' && $site !== 'none') {
            throw new ForbiddenHttpException('Cross-site form submissions are not accepted.');
        }

        $origin = $request->getHeaderLine('Origin');
        if ($origin !== '' && $origin !== 'null' && strtolower((string) parse_url($origin, PHP_URL_HOST)) !== strtolower($request->getUri()->getHost())) {
            throw new ForbiddenHttpException('Cross-site form submissions are not accepted.');
        }

        $body = $request->getParsedBody();
        $fields = is_array($body) ? $body : [];
        $token = $fields[CsrfTokens::FIELD] ?? $request->getHeaderLine(CsrfTokens::HEADER);
        $form = $fields[CsrfTokens::FORM_FIELD] ?? CsrfTokens::DEFAULT_FORM;

        if (!is_string($token) || $token === '' || !is_string($form) || !$this->tokens->verify($token, $form)) {
            throw new ForbiddenHttpException('The form has expired or is invalid. Reload the page and try again.');
        }

        return $handler->handle($request);
    }
}
