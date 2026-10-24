<?php

declare(strict_types=1);

namespace Zana\Security\Middleware;

use Closure;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Zana\Security\Attribute\RequiresAuthentication;
use Zana\Security\Attribute\RequiresPermission;
use Zana\Security\Authorizer;
use Zana\Security\SecurityContext;

/**
 * Enforces #[RequiresAuthentication] and #[RequiresPermission] on the
 * matched handler (the "_handler" request attribute routing sets), so it runs
 * as route middleware, after AuthenticationMiddleware:
 *
 *     $router->group('/admin', $routes, [AuthorizationMiddleware::class]);
 */
final readonly class AuthorizationMiddleware implements MiddlewareInterface
{
    public function __construct(
        private SecurityContext $context,
        private Authorizer $authorizer,
    ) {
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        [$authenticate, $permissions] = self::requirements($request->getAttribute('_handler'));

        if ($authenticate || $permissions !== []) {
            $user = $this->context->requireUser();
            foreach ($permissions as $permission) {
                $this->authorizer->authorize($user, $permission);
            }
        }

        return $handler->handle($request);
    }

    /**
     * @return array{bool, list<string>} whether authentication is required, and the permissions
     */
    private static function requirements(mixed $handler): array
    {
        $targets = match (true) {
            $handler instanceof Closure => [new \ReflectionFunction($handler)],
            is_string($handler) && class_exists($handler) => self::classAndMethod($handler, '__invoke'),
            is_array($handler) && is_string($handler[0] ?? null) && is_string($handler[1] ?? null) && class_exists($handler[0]) => self::classAndMethod($handler[0], $handler[1]),
            default => [],
        };

        $authenticate = false;
        $permissions = [];
        foreach ($targets as $target) {
            $authenticate = $authenticate || $target->getAttributes(RequiresAuthentication::class) !== [];
            foreach ($target->getAttributes(RequiresPermission::class) as $attribute) {
                $permissions[] = $attribute->newInstance()->permission;
            }
        }

        return [$authenticate, array_values(array_unique($permissions))];
    }

    /**
     * @param class-string $class
     *
     * @return list<\ReflectionClass<object>|\ReflectionMethod>
     */
    private static function classAndMethod(string $class, string $method): array
    {
        $reflection = new \ReflectionClass($class);

        return $reflection->hasMethod($method) ? [$reflection, $reflection->getMethod($method)] : [$reflection];
    }
}
