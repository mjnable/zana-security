<?php

declare(strict_types=1);

namespace Zana\Security\Inspection;

use Zana\Configuration\ConfigurationInterface;
use Zana\Core\ApplicationInterface;
use Zana\Core\Inspection\ApplicationCheck;
use Zana\Core\Inspection\Finding;
use Zana\Core\Inspection\SecurityRules;
use Zana\Core\Inspection\Severity;
use Zana\Routing\Attribute\PublicRoute;
use Zana\Routing\Route;
use Zana\Routing\Router;
use Zana\Security\Attribute\RateLimit;
use Zana\Security\Attribute\RequiresAuthentication;
use Zana\Security\Attribute\RequiresPermission;
use Zana\Security\Attribute\WithoutCsrf;
use Zana\Security\Internal\HandlerReflection;
use Zana\Security\Middleware\AuthorizationMiddleware;
use Zana\Security\Middleware\CsrfMiddleware;
use Zana\Security\Middleware\RateLimitMiddleware;
use Zana\Security\Session\SessionAuthenticationMiddleware;

/**
 * The security rules for routes (2.21, FE-68, ADR-033). Errors with
 * security.strict, warnings otherwise, except where noted:
 *
 * - security.route_access: a route says nothing about who may reach it.
 *   It needs #[PublicRoute(reason: …)] (or a public group), or
 *   #[RequiresAuthentication] / #[RequiresPermission].
 * - security.access_unenforced: a route requires a user or a permission, but
 *   AuthorizationMiddleware is not on the route, so nothing enforces it.
 *   Authentication middleware alone is no protection: it lets anonymous
 *   requests through.
 * - security.global_middleware: AuthorizationMiddleware or
 *   RateLimitMiddleware in http.middleware, where it runs before routing and
 *   so enforces nothing.
 * - security.csrf: a route that changes data, with session sign-in, and no
 *   CsrfMiddleware (route or global) and no #[WithoutCsrf].
 * - security.rate_limit, always a warning: a public route that changes data
 *   without #[RateLimit] and RateLimitMiddleware. A form behind a CAPTCHA is
 *   a false alarm.
 */
final readonly class RouteAccessCheck implements ApplicationCheck
{
    private const array UNSAFE = ['POST', 'PUT', 'PATCH', 'DELETE'];

    /** By name: mj-zana/session is optional. */
    private const string SESSION_MIDDLEWARE = 'Zana\Session\SessionMiddleware';

    public function findings(ApplicationInterface $application): array
    {
        $container = $application->container();
        if (!class_exists(Router::class) || !$container->has(Router::class)) {
            return [];
        }
        $router = $container->get(Router::class);
        $config = $container->get(ConfigurationInterface::class);
        assert($router instanceof Router && $config instanceof ConfigurationInterface);

        $strict = SecurityRules::severity($application);
        $global = array_values(array_filter($config->array('http.middleware', []), is_string(...)));
        $findings = [];

        foreach ([AuthorizationMiddleware::class => '#[RequiresAuthentication] and #[RequiresPermission]', RateLimitMiddleware::class => '#[RateLimit]'] as $middleware => $what) {
            if (self::has($global, $middleware)) {
                $findings[] = new Finding(
                    'security.global_middleware',
                    $strict,
                    "{$middleware} is in http.middleware, where it runs before routing: it sees no handler, so it enforces none of {$what}.",
                    hint: 'Put it on the routes instead: $router->group(\'/admin\', $routes, [' . self::short($middleware) . '::class]), or middleware: [...] in #[Route].',
                    security: true,
                );
            }
        }

        foreach ($router->routes() as $route) {
            $where = implode('|', $route->methods) . ' ' . $route->path;
            $handler = $route->handler;
            $middleware = $route->getMiddleware();
            $requiresUser = HandlerReflection::has($handler, RequiresAuthentication::class) || HandlerReflection::has($handler, RequiresPermission::class);
            $public = PublicRoute::reasonFor($route);
            $changesData = array_intersect($route->methods, self::UNSAFE) !== [];

            if (!$requiresUser && $public === null) {
                $findings[] = new Finding(
                    'security.route_access',
                    $strict,
                    "{$where} does not say who may reach it.",
                    self::file($handler),
                    hint: 'Add #[RequiresAuthentication] or #[RequiresPermission(\'…\')] with AuthorizationMiddleware on the route, or #[PublicRoute(reason: \'…\')] if anyone may reach it.',
                    security: true,
                );
            }
            if ($requiresUser && !self::has($middleware, AuthorizationMiddleware::class)) {
                $findings[] = new Finding(
                    'security.access_unenforced',
                    $strict,
                    "{$where} requires a user, but AuthorizationMiddleware is not on the route, so anyone reaches it."
                        . ($public === null ? '' : ' It also says it is public, which contradicts that.'),
                    self::file($handler),
                    hint: $public === null
                        ? 'Add AuthorizationMiddleware to the route or its group. Authentication middleware alone lets anonymous requests through.'
                        : 'If anyone may reach it on purpose, such as a preview link checked by its token, move it to a class without #[RequiresAuthentication] or #[RequiresPermission], and keep #[PublicRoute] there. Otherwise add AuthorizationMiddleware.',
                    security: true,
                );
            }
            if ($changesData) {
                $all = [...$global, ...$middleware];
                $sessions = self::has($all, self::SESSION_MIDDLEWARE) || self::has($all, SessionAuthenticationMiddleware::class);
                if ($sessions && !self::has($all, CsrfMiddleware::class) && !HandlerReflection::has($handler, WithoutCsrf::class)) {
                    $findings[] = new Finding(
                        'security.csrf',
                        $strict,
                        "{$where} changes data with session sign-in, and nothing checks that the request comes from this site.",
                        self::file($handler),
                        hint: 'Add CsrfMiddleware to the route or http.middleware, and csrf_field() to the form; or #[WithoutCsrf] on a handler that checks requests itself, such as a signed webhook.',
                        security: true,
                    );
                }
                if ($public !== null && !(HandlerReflection::has($handler, RateLimit::class) && self::has($middleware, RateLimitMiddleware::class))) {
                    $findings[] = new Finding(
                        'security.rate_limit',
                        Severity::Warning,
                        "{$where} is public and changes data, with no rate limit: anyone can send it as often as they like.",
                        self::file($handler),
                        hint: 'Add #[RateLimit(max: …, per: …)] and RateLimitMiddleware on the route. Ignore this for a form protected otherwise, e.g. by a CAPTCHA.',
                        security: true,
                    );
                }
            }
        }

        return $findings;
    }

    /**
     * @param list<mixed> $middleware Class names or instances
     */
    private static function has(array $middleware, string $class): bool
    {
        foreach ($middleware as $item) {
            if ((is_string($item) && is_a($item, $class, true)) || $item instanceof $class) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param \Closure|string|array{0: string, 1: string} $handler
     */
    private static function file(\Closure|string|array $handler): ?string
    {
        foreach (array_reverse(HandlerReflection::targets($handler)) as $target) {   // the method or closure first, then the class
            $file = $target->getFileName();
            if ($file !== false) {
                return str_replace('\\', '/', $file) . ($target instanceof \ReflectionClass ? '' : ':' . $target->getStartLine());
            }
        }

        return null;
    }

    private static function short(string $class): string
    {
        return substr($class, (int) strrpos($class, '\\') + 1);
    }
}
