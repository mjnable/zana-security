<?php

declare(strict_types=1);

namespace Zana\Security\Inspection;

use Zana\Configuration\ConfigurationInterface;
use Zana\Core\ApplicationInterface;
use Zana\Core\Inspection\ApplicationCheck;
use Zana\Core\Inspection\Finding;
use Zana\Core\Inspection\SecurityRules;
use Zana\Core\Inspection\Severity;
use Zana\Routing\Router;
use Zana\Security\Internal\HandlerReflection;
use Zana\Security\Middleware\AuthorizationMiddleware;
use Zana\Security\Middleware\RateLimitMiddleware;

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
 *
 * An application's own sign-in middleware (2.21, ADR-033 amendment) counts
 * when it is declared, with the reason it refuses anonymous visitors:
 *
 *     'access_middleware' => [App\Web\SignedIn::class => 'Sends visitors without an API session to sign in'],
 *
 * A route counts as needing a user only when that middleware is on the route
 * or its group, not in http.middleware. It never counts as a permission
 * check: #[RequiresPermission] still needs AuthorizationMiddleware. check says
 * which routes rely on it (security.application_access, info), and reports a
 * declaration it cannot accept (security.access_middleware): an empty reason,
 * a class that is not a middleware, or Zana's own middleware, none of which
 * refuses anonymous visitors by itself.
 *
 * Each route is read through RouteAccess (2.22), as mj-zana/testing's attacks read it.
 */
final readonly class RouteAccessCheck implements ApplicationCheck
{
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
            if (RouteAccess::has($global, $middleware)) {
                $findings[] = new Finding(
                    'security.global_middleware',
                    $strict,
                    "{$middleware} is in http.middleware, where it runs before routing: it sees no handler, so it enforces none of {$what}.",
                    hint: 'Put it on the routes instead: $router->group(\'/admin\', $routes, [' . self::short($middleware) . '::class]), or middleware: [...] in #[Route].',
                    security: true,
                );
            }
        }

        $problems = [];
        $declared = RouteAccess::declaredMiddleware($config, $problems);
        foreach ($problems as $problem) {
            $findings[] = new Finding(
                'security.access_middleware',
                $strict,
                $problem,
                hint: 'Name the class of a middleware that refuses anonymous visitors, with how it does: App\\Web\\SignedIn::class => \'Sends visitors without an API session to sign in\'. Zana\'s own protection is #[RequiresAuthentication] or #[RequiresPermission] with AuthorizationMiddleware.',
                security: true,
            );
        }
        $covered = array_fill_keys(array_keys($declared), []);

        foreach ($router->routes() as $route) {
            $access = RouteAccess::of($route, $global, $declared);
            $where = implode('|', $route->methods) . ' ' . $route->path;
            $handler = $route->handler;

            if ($access->application !== null) {
                $covered[$access->application][] = $where;
            }
            if (!$access->declared()) {
                $findings[] = new Finding(
                    'security.route_access',
                    $strict,
                    "{$where} does not say who may reach it.",
                    self::file($handler),
                    hint: 'Add #[RequiresAuthentication] or #[RequiresPermission(\'…\')] with AuthorizationMiddleware on the route, or #[PublicRoute(reason: \'…\')] if anyone may reach it. An application\'s own sign-in middleware counts when it is declared in security.access_middleware.',
                    security: true,
                );
            }
            if ($access->requiresUser && !$access->authorized) {
                $findings[] = new Finding(
                    'security.access_unenforced',
                    $strict,
                    "{$where} requires a user, but AuthorizationMiddleware is not on the route, so anyone reaches it."
                        . ($access->public === null ? '' : ' It also says it is public, which contradicts that.'),
                    self::file($handler),
                    hint: $access->public === null
                        ? 'Add AuthorizationMiddleware to the route or its group. Authentication middleware alone lets anonymous requests through.'
                        : 'If anyone may reach it on purpose, such as a preview link checked by its token, move it to a class without #[RequiresAuthentication] or #[RequiresPermission], and keep #[PublicRoute] there. Otherwise add AuthorizationMiddleware.',
                    security: true,
                );
            }
            if ($access->changesData) {
                if ($access->sessions && !$access->csrfProtected && !$access->withoutCsrf) {
                    $findings[] = new Finding(
                        'security.csrf',
                        $strict,
                        "{$where} changes data with session sign-in, and nothing checks that the request comes from this site.",
                        self::file($handler),
                        hint: 'Add CsrfMiddleware to the route or http.middleware, and csrf_field() to the form; or #[WithoutCsrf] on a handler that checks requests itself, such as a signed webhook.',
                        security: true,
                    );
                }
                if ($access->public !== null && $access->rateLimit === null) {
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

        foreach ($covered as $class => $routes) {
            $findings[] = $routes === []
                ? new Finding(
                    'security.application_access',
                    Severity::Warning,
                    "{$class} is declared in security.access_middleware, but runs on no route, so it protects nothing.",
                    hint: 'Add it to the routes or groups it protects, or remove the declaration.',
                    security: true,
                )
                : new Finding(
                    'security.application_access',
                    Severity::Info,
                    count($routes) . " route(s) count as needing a user because {$class} runs on them, as the application declares: "
                        . "\"{$declared[$class]}\". Zana does not check that it refuses anonymous visitors, nor any permission: "
                        . 'those stay the application\'s. ' . implode(', ', array_slice($routes, 0, 5)) . (count($routes) > 5 ? ', …' : '') . '.',
                    security: true,
                );
        }

        return $findings;
    }

    /**
     * @param \Closure|string|array{0: string, 1: string} $handler
     */
    private static function file(\Closure|string|array $handler): ?string
    {
        return HandlerReflection::location($handler);
    }

    private static function short(string $class): string
    {
        return substr($class, (int) strrpos($class, '\\') + 1);
    }
}
