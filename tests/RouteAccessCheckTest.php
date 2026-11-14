<?php

declare(strict_types=1);

namespace Zana\Security\Tests;

use PHPUnit\Framework\TestCase;
use Zana\Core\Application;
use Zana\Core\ApplicationInterface;
use Zana\Core\Inspection\Finding;
use Zana\Core\Inspection\Severity;
use Zana\Http\HttpServiceProvider;
use Zana\Routing\Attribute\PublicRoute;
use Zana\Routing\Router;
use Zana\Routing\RoutingServiceProvider;
use Zana\Security\Attribute\RateLimit;
use Zana\Security\Attribute\RequiresAuthentication;
use Zana\Security\Attribute\RequiresPermission;
use Zana\Security\Attribute\WithoutCsrf;
use Zana\Security\Inspection\RouteAccessCheck;
use Zana\Security\Middleware\AuthenticationMiddleware;
use Zana\Security\Middleware\AuthorizationMiddleware;
use Zana\Security\Middleware\CsrfMiddleware;
use Zana\Security\Middleware\RateLimitMiddleware;
use Zana\Security\SecurityServiceProvider;
use Zana\Security\Session\SessionAuthenticationMiddleware;
use Zana\Session\SessionMiddleware;

/**
 * 2.21, FE-68, ADR-033: check reports a route that does not say who may
 * reach it, an access rule nothing enforces, a session form without CSRF
 * protection, and a public form without a rate limit.
 */
final class RouteAccessCheckTest extends TestCase
{
    public function testARouteThatSaysNothingIsReported(): void
    {
        $findings = $this->findings(static function (Router $r): void {
            $r->get('/admin/users', [UndeclaredController::class, 'index']);
            $r->get('/closure', static fn (): string => 'x');
            $r->get('/about', [WebsitePages::class, 'about']);
            $r->get('/ping', #[PublicRoute(reason: 'Uptime checks')] static fn (): string => 'pong');
            $r->group('/site', static fn (Router $r) => $r->get('/home', [UndeclaredController::class, 'index']), public: 'The public website');
            $r->get('/me', [ProtectedController::class, 'me'])->middleware(AuthorizationMiddleware::class);
            $r->redirect('/old', '/about');
        });

        $this->assertSame(['security.route_access GET /admin/users', 'security.route_access GET /closure'], self::summary($findings));
        $this->assertStringContainsString('RouteAccessCheckTest.php:', (string) $findings[0]->file, 'it points at the handler');
        $this->assertTrue($findings[0]->security);
    }

    public function testRulesAreWarningsUnlessStrict(): void
    {
        $routes = static fn (Router $r) => $r->get('/admin/users', [UndeclaredController::class, 'index']);

        $this->assertSame(Severity::Warning, $this->findings($routes)[0]->severity, 'an upgrade fails nobody (ADR-003)');
        $this->assertSame(Severity::Error, $this->findings($routes, strict: true)[0]->severity);
    }

    public function testAPublicMethodOnAClassThatRequiresAUserIsAContradiction(): void
    {
        // Found in zanabler: a preview link, checked by its token, on an admin controller that requires a permission.
        $findings = $this->findings(static fn (Router $r) => $r->get('/preview/{token}', [EditorController::class, 'preview']), strict: true);

        $this->assertSame(['security.access_unenforced GET /preview/{token}'], self::summary($findings));
        $this->assertStringContainsString('It also says it is public, which contradicts that.', $findings[0]->message);
        $this->assertStringContainsString('move it to a class without', (string) $findings[0]->hint);
    }

    public function testAnAccessRuleNothingEnforcesIsReported(): void
    {
        // The audit's lesson: an attribute nobody enforces looks safe and is not.
        $findings = $this->findings(static function (Router $r): void {
            $r->get('/me', [ProtectedController::class, 'me']);                                                      // no middleware at all
            $r->get('/token', [ProtectedController::class, 'me'])->middleware(AuthenticationMiddleware::class);       // lets anonymous through
            $r->get('/session', [ProtectedController::class, 'me'])->middleware(SessionMiddleware::class, SessionAuthenticationMiddleware::class);
            $r->get('/report', [ProtectedController::class, 'report']);                                              // a permission, too
            $r->group('/ok', static fn (Router $r) => $r->get('/me', [ProtectedController::class, 'me']), [AuthorizationMiddleware::class]);
        }, strict: true);

        $this->assertSame([
            'security.access_unenforced GET /me',
            'security.access_unenforced GET /token',
            'security.access_unenforced GET /session',
            'security.access_unenforced GET /report',
        ], self::summary($findings));
        $this->assertSame(Severity::Error, $findings[0]->severity);
    }

    public function testRouteOnlyMiddlewareInHttpMiddlewareIsReported(): void
    {
        $findings = $this->findings(
            static fn (Router $r) => $r->get('/me', [ProtectedController::class, 'me'])->middleware(AuthorizationMiddleware::class),
            ['http.middleware' => [AuthorizationMiddleware::class, RateLimitMiddleware::class, CsrfMiddleware::class]],
        );

        $this->assertSame(['security.global_middleware', 'security.global_middleware'], array_map(static fn (Finding $f): string => $f->id, $findings));
        $this->assertStringContainsString(AuthorizationMiddleware::class . ' is in http.middleware', $findings[0]->message);
        $this->assertStringContainsString(RateLimitMiddleware::class, $findings[1]->message);
    }

    public function testASessionFormWithoutCsrfProtectionIsReported(): void
    {
        $findings = $this->findings(static function (Router $r): void {
            $r->group('', static function (Router $r): void {
                $r->post('/contact', [WebsitePages::class, 'contact']);                              // reported
                $r->post('/webhook', [WebsitePages::class, 'webhook']);                              // #[WithoutCsrf]
                $r->post('/guarded', [WebsitePages::class, 'guarded'])->middleware(CsrfMiddleware::class);
                $r->get('/about', [WebsitePages::class, 'about']);                                   // reads only
            }, [SessionMiddleware::class]);
            $r->post('/api/orders', [ApiController::class, 'store'])->middleware(AuthenticationMiddleware::class, AuthorizationMiddleware::class);  // tokens, no session
        }, strict: true);

        $this->assertSame(['security.csrf POST /contact'], array_values(array_filter(self::summary($findings), static fn (string $s): bool => str_starts_with($s, 'security.csrf'))));
        $this->assertSame([], array_values(array_filter(
            self::summary($this->findings(static fn (Router $r) => $r->post('/contact', [WebsitePages::class, 'contact'])->middleware(SessionMiddleware::class), ['http.middleware' => [CsrfMiddleware::class]], true)),
            static fn (string $s): bool => str_starts_with($s, 'security.csrf'),
        )), 'CsrfMiddleware in http.middleware protects every route');
    }

    public function testAPublicFormWithoutARateLimitIsAWarningEvenInStrictMode(): void
    {
        $findings = $this->findings(static function (Router $r): void {
            $r->post('/contact', [WebsitePages::class, 'contact'])->middleware(CsrfMiddleware::class);
            $r->post('/limited', [WebsitePages::class, 'limited'])->middleware(CsrfMiddleware::class, RateLimitMiddleware::class);
            $r->post('/attribute-only', [WebsitePages::class, 'limited'])->middleware(CsrfMiddleware::class);   // nothing enforces it
        }, strict: true);

        $limits = array_values(array_filter($findings, static fn (Finding $f): bool => $f->id === 'security.rate_limit'));
        $this->assertSame(['security.rate_limit POST /contact', 'security.rate_limit POST /attribute-only'], self::summary($limits));
        $this->assertSame(Severity::Warning, $limits[0]->severity, 'false alarms, e.g. a form behind a CAPTCHA');
    }

    /**
     * @param \Closure(Router): mixed $routes
     * @param array<string, mixed> $config
     * @return list<Finding>
     */
    private function findings(\Closure $routes, array $config = [], bool $strict = false): array
    {
        $app = Application::configure(sys_get_temp_dir() . '/zana-security-routes')
            ->withEnvironment('testing')
            ->withConfiguration(['security.secret' => str_repeat('s', 40), 'security.strict' => $strict, ...$config])
            ->withProviders(HttpServiceProvider::class, RoutingServiceProvider::class, SecurityServiceProvider::class)
            ->build();
        $router = $app->container()->get(Router::class);
        assert($router instanceof Router);
        $routes($router);

        return self::check($app);
    }

    /**
     * @return list<Finding>
     */
    private static function check(ApplicationInterface $app): array
    {
        foreach ($app->container()->tagged(\Zana\Core\Inspection\ApplicationCheck::TAG) as $check) {
            if ($check instanceof RouteAccessCheck) {
                return $check->findings($app);
            }
        }
        self::fail('RouteAccessCheck is not tagged.');
    }

    /**
     * @param list<Finding> $findings
     * @return list<string>
     */
    private static function summary(array $findings): array
    {
        return array_map(static fn (Finding $f): string => $f->id . ' ' . strtok($f->message, ' ') . ' ' . explode(' ', $f->message)[1], $findings);
    }
}

final class UndeclaredController
{
    public function index(): string
    {
        return 'users';
    }
}

#[PublicRoute(reason: 'The pages of the public website')]
final class WebsitePages
{
    public function about(): string
    {
        return 'about';
    }

    public function contact(): string
    {
        return 'sent';
    }

    #[WithoutCsrf]
    public function webhook(): string
    {
        return 'ok';
    }

    public function guarded(): string
    {
        return 'ok';
    }

    #[RateLimit(max: 5, per: 3600)]
    public function limited(): string
    {
        return 'ok';
    }
}

#[RequiresAuthentication]
final class ProtectedController
{
    public function me(): string
    {
        return 'me';
    }

    #[RequiresPermission('reports.view')]
    public function report(): string
    {
        return 'report';
    }
}

#[RequiresPermission('articles.edit')]
final class EditorController
{
    #[PublicRoute(reason: 'A preview link: the signed token is the access')]
    public function preview(string $token): string
    {
        return $token;
    }
}

final class ApiController
{
    #[RequiresPermission('orders.create')]
    public function store(): string
    {
        return 'created';
    }
}
