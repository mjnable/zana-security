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
use Zana\Security\RoleAssignment\Scope;
use Zana\Security\SecurityContext;
use Zana\Security\SecurityException;

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
            foreach ($permissions as $required) {
                $this->authorizer->authorize($user, $required->permission, self::scope($required, $request));
            }
        }

        return $handler->handle($request);
    }

    /**
     * @return array{bool, list<RequiresPermission>} whether authentication is required, and the permissions
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
                $required = $attribute->newInstance();
                $permissions[$required->permission . "\n" . $required->scope . "\n" . $required->parameter()] = $required;
            }
        }

        return [$authenticate, array_values($permissions)];
    }

    /**
     * The scope a scoped #[RequiresPermission] names, read from the route parameter (2.17).
     */
    private static function scope(RequiresPermission $required, ServerRequestInterface $request): ?Scope
    {
        $parameter = $required->parameter();
        if ($required->scope === null || $parameter === null) {
            return null;
        }
        $id = $request->getAttribute($parameter);
        if (!is_scalar($id) || (string) $id === '') {
            throw new SecurityException("#[RequiresPermission('{$required->permission}', scope: '{$required->scope}')] needs the route parameter {$parameter}; name it in the route path, or pass parameter:.");
        }

        return new Scope($required->scope, (string) $id);
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
