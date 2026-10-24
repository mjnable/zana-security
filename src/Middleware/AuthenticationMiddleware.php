<?php

declare(strict_types=1);

namespace Zana\Security\Middleware;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Zana\Http\Exception\UnauthorizedHttpException;
use Zana\Security\InvalidTokenException;
use Zana\Security\SecurityContext;
use Zana\Security\TokenSigner;
use Zana\Security\UserProviderInterface;

/**
 * Authenticates "Authorization: Bearer <token>" requests. Requests without
 * the header pass through anonymously; a bad header, token or user is a 401.
 * The user is set on the SecurityContext and as the request attribute "user".
 */
final readonly class AuthenticationMiddleware implements MiddlewareInterface
{
    public const string ATTRIBUTE = 'user';

    public function __construct(
        private TokenSigner $signer,
        private UserProviderInterface $users,
        private SecurityContext $context,
    ) {
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $header = $request->getHeaderLine('Authorization');
        if ($header === '') {
            return $handler->handle($request);
        }

        if (preg_match('/^Bearer\s+(\S+)$/i', trim($header), $match) !== 1) {
            throw self::unauthorized('The Authorization header must use the Bearer scheme.');
        }

        try {
            $claims = $this->signer->verify($match[1]);
        } catch (InvalidTokenException $e) {
            throw self::unauthorized($e->getMessage(), $e);
        }

        $user = $this->users->findByIdentifier($claims->subject) ?? throw self::unauthorized('The token user does not exist.');
        $this->context->setUser($user);

        return $handler->handle($request->withAttribute(self::ATTRIBUTE, $user));
    }

    private static function unauthorized(string $message, ?\Throwable $previous = null): UnauthorizedHttpException
    {
        return new UnauthorizedHttpException($message, ['WWW-Authenticate' => 'Bearer'], $previous);
    }
}
