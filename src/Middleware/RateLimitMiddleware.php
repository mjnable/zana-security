<?php

declare(strict_types=1);

namespace Zana\Security\Middleware;

use Closure;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Zana\Http\Exception\TooManyRequestsHttpException;
use Zana\Security\Attribute\RateLimit;
use Zana\Security\Internal\HandlerReflection;
use Zana\Security\RateLimit\RateLimiter;
use Zana\Security\SecurityContext;

/**
 * Enforces #[RateLimit] on the matched handler, so it runs as route
 * middleware. Refused requests get 429 with Retry-After; every limited
 * response carries RateLimit-Limit, -Remaining and -Reset.
 *
 * The client address is the "client_ip" attribute that TrustedProxiesMiddleware
 * sets behind a proxy or CDN, otherwise REMOTE_ADDR.
 */
final readonly class RateLimitMiddleware implements MiddlewareInterface
{
    public function __construct(
        private RateLimiter $limiter,
        private ?SecurityContext $security = null,
    ) {
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $target = $request->getAttribute('_handler');
        $limit = HandlerReflection::firstAttribute($target, RateLimit::class);
        if ($limit === null) {
            return $handler->handle($request);
        }

        $result = $this->limiter->attempt($this->key($limit, $request, $target), $limit->max, $limit->per, $limit->strategy);
        if (!$result->allowed) {
            throw new TooManyRequestsHttpException($result->resetAfter, headers: $result->headers());
        }

        $response = $handler->handle($request);
        foreach ($result->headers() as $name => $value) {
            $response = $response->withHeader($name, $value);
        }

        return $response;
    }

    private function key(RateLimit $limit, ServerRequestInterface $request, mixed $target): string
    {
        $name = $limit->name ?? match (true) {
            $target instanceof Closure => 'closure:' . spl_object_id($target),
            is_array($target) => implode('::', array_map('strval', $target)),
            default => is_string($target) ? $target : 'handler',
        };

        $client = $request->getAttribute('client_ip') ?? $request->getServerParams()['REMOTE_ADDR'] ?? 'unknown';
        $who = match ($limit->by) {
            'global' => 'all',
            'user' => $this->security?->user()?->identifier() !== null ? 'user:' . $this->security->user()->identifier() : 'ip:' . (is_string($client) ? $client : 'unknown'),
            default => 'ip:' . (is_string($client) ? $client : 'unknown'),
        };

        return "{$name}|{$who}";
    }
}
