<?php

declare(strict_types=1);

namespace Zana\Security\Inspection;

use Psr\Http\Server\MiddlewareInterface;
use Zana\Configuration\ConfigurationInterface;
use Zana\Routing\Attribute\PublicRoute;
use Zana\Routing\Route;
use Zana\Security\Attribute\RateLimit;
use Zana\Security\Attribute\RequiresAuthentication;
use Zana\Security\Attribute\RequiresPermission;
use Zana\Security\Attribute\WithoutCsrf;
use Zana\Security\Internal\HandlerReflection;
use Zana\Security\Middleware\AuthenticationMiddleware;
use Zana\Security\Middleware\AuthorizationMiddleware;
use Zana\Security\Middleware\CsrfMiddleware;
use Zana\Security\Middleware\RateLimitMiddleware;
use Zana\Security\Session\SessionAuthenticationMiddleware;

/**
 * Who may reach one route, as its declarations and middleware say (2.22,
 * FE-68). The security rules of `check` (layer 1) and the attacks of
 * mj-zana/testing (layer 2) both read it, so they judge every route alike.
 *
 *     $access = RouteAccess::of($route, $httpMiddleware, RouteAccess::declaredMiddleware($config));
 *     $access->needsUser();   // anonymous requests must not reach its handler
 *
 * @api
 */
final readonly class RouteAccess
{
    private const array UNSAFE = ['POST', 'PUT', 'PATCH', 'DELETE'];

    /** By name: mj-zana/session is optional. */
    private const string SESSION_MIDDLEWARE = 'Zana\Session\SessionMiddleware';

    /** Zana's middleware that security.access_middleware cannot name, and why. */
    public const array NOT_ACCESS_MIDDLEWARE = [
        AuthenticationMiddleware::class => 'it identifies a user when there is one, and lets anonymous requests through.',
        SessionAuthenticationMiddleware::class => 'it identifies a user when there is one, and lets anonymous requests through.',
        AuthorizationMiddleware::class => 'it enforces #[RequiresAuthentication] and #[RequiresPermission], and does nothing on a route without them.',
        CsrfMiddleware::class => 'it checks where a request comes from, not who sends it.',
        RateLimitMiddleware::class => 'it limits how often, not who.',
    ];

    /**
     * @param string|null $public Why anyone may reach it, when it says so
     * @param bool $requiresUser #[RequiresAuthentication] or #[RequiresPermission] on its handler
     * @param bool $authorized AuthorizationMiddleware is on the route, which enforces those
     * @param class-string|null $application The application's declared sign-in middleware on the route
     * @param bool $sessions Session sign-in runs for the route (route or http.middleware)
     * @param bool $csrfProtected CsrfMiddleware runs for the route, and the handler does not opt out
     * @param RateLimit|null $rateLimit The limit enforced on the route: the attribute with RateLimitMiddleware on the route
     * @param list<string> $permissions The permissions #[RequiresPermission] names on its handler
     */
    private function __construct(
        public Route $route,
        public ?string $public,
        public bool $requiresUser,
        public bool $authorized,
        public ?string $application,
        public bool $changesData,
        public bool $sessions,
        public bool $csrfProtected,
        public bool $withoutCsrf,
        public ?RateLimit $rateLimit,
        public bool $rateLimitDeclared,
        public array $permissions = [],
    ) {
    }

    /**
     * @param list<mixed> $httpMiddleware The application's http.middleware
     * @param array<class-string, string> $declared From declaredMiddleware()
     */
    public static function of(Route $route, array $httpMiddleware, array $declared): self
    {
        $handler = $route->handler;
        $middleware = $route->getMiddleware();
        $application = null;
        foreach (array_keys($declared) as $class) {
            if (self::has($middleware, $class)) {
                $application = $class;
                break;
            }
        }
        $all = [...$httpMiddleware, ...$middleware];
        $withoutCsrf = HandlerReflection::has($handler, WithoutCsrf::class);
        $limit = HandlerReflection::firstAttribute($handler, RateLimit::class);
        $permissions = [];
        foreach (HandlerReflection::targets($handler) as $target) {
            foreach ($target->getAttributes(RequiresPermission::class) as $attribute) {
                $permissions[] = $attribute->newInstance()->permission;
            }
        }

        return new self(
            $route,
            PublicRoute::reasonFor($route),
            HandlerReflection::has($handler, RequiresAuthentication::class) || HandlerReflection::has($handler, RequiresPermission::class),
            self::has($middleware, AuthorizationMiddleware::class),
            $application,
            array_intersect($route->methods, self::UNSAFE) !== [],
            self::has($all, self::SESSION_MIDDLEWARE) || self::has($all, SessionAuthenticationMiddleware::class),
            self::has($all, CsrfMiddleware::class) && !$withoutCsrf,
            $withoutCsrf,
            $limit !== null && self::has($middleware, RateLimitMiddleware::class) ? $limit : null,
            $limit !== null,
            array_values(array_unique($permissions)),
        );
    }

    /**
     * The application's own access middleware it declares in
     * security.access_middleware, each with the reason it refuses anonymous
     * visitors. A declaration that cannot be accepted is left out, and
     * described in $problems.
     *
     * @param list<string> $problems
     * @return array<class-string, string>
     */
    public static function declaredMiddleware(ConfigurationInterface $config, array &$problems = []): array
    {
        $declared = [];
        foreach ($config->array('security.access_middleware', []) as $class => $reason) {
            $name = is_string($class) ? $class : var_export($class, true);
            if (!is_string($class) || !class_exists($class) || !is_a($class, MiddlewareInterface::class, true)) {
                $problems[] = "security.access_middleware names {$name}, which is not a middleware class.";
                continue;
            }
            if (!is_string($reason) || trim($reason) === '') {
                $problems[] = "security.access_middleware gives no reason for {$class}.";
                continue;
            }
            foreach (self::NOT_ACCESS_MIDDLEWARE as $zana => $why) {
                if (is_a($class, $zana, true)) {
                    $problems[] = "security.access_middleware names {$class}: {$why}";
                    continue 2;
                }
            }
            $declared[$class] = trim($reason);
        }

        return $declared;
    }

    /**
     * Anonymous requests must not reach its handler: Zana's access rule is
     * enforced on it, or the application's declared sign-in middleware runs.
     */
    public function needsUser(): bool
    {
        return ($this->requiresUser && $this->authorized) || $this->application !== null;
    }

    /**
     * It says only users may reach it: a Zana access rule, enforced or not, or
     * the application's declared sign-in middleware. The attacks of
     * mj-zana/testing test this claim against what the route does.
     */
    public function claimsUser(): bool
    {
        return $this->requiresUser || $this->application !== null;
    }

    /**
     * It says who may reach it, one way or another.
     */
    public function declared(): bool
    {
        return $this->requiresUser || $this->public !== null || $this->application !== null;
    }

    /**
     * @param list<mixed> $middleware Class names or instances
     */
    public static function has(array $middleware, string $class): bool
    {
        foreach ($middleware as $item) {
            if ((is_string($item) && is_a($item, $class, true)) || $item instanceof $class) {
                return true;
            }
        }

        return false;
    }
}
