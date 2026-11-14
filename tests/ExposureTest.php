<?php

declare(strict_types=1);

namespace Zana\Security\Tests;

use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Tester\ApplicationTester;
use Zana\Configuration\ConfigurationInterface;
use Zana\Console\ConsoleKernel;
use Zana\Console\ConsoleServiceProvider;
use Zana\Core\Application;
use Zana\Core\ApplicationInterface;
use Zana\Core\Inspection\ApplicationCheck;
use Zana\Core\Inspection\Finding;
use Zana\Core\Inspection\Severity;
use Zana\Http\HttpServiceProvider;
use Zana\Routing\Attribute\PublicRoute;
use Zana\Routing\Router;
use Zana\Routing\RoutingServiceProvider;
use Zana\Security\Attribute\RequiresPermission;
use Zana\Security\Inspection\Exposure;
use Zana\Security\Inspection\ExposureCheck;
use Zana\Security\Middleware\AuthorizationMiddleware;
use Zana\Security\SecurityServiceProvider;

/**
 * 2.23, FE-68 layer 4, ADR-033: security/exposure.json records who may reach
 * each route, security:exposure writes it, and check reports a route that is
 * new or whose access changed until it is written again.
 */
final class ExposureTest extends TestCase
{
    private string $base;

    protected function setUp(): void
    {
        $this->base = sys_get_temp_dir() . '/zana-exposure-' . bin2hex(random_bytes(4));
        mkdir($this->base);
    }

    protected function tearDown(): void
    {
        @unlink("{$this->base}/security/exposure.json");
        @rmdir("{$this->base}/security");
        @rmdir($this->base);
    }

    public function testEachRouteIsRecordedAsWhatItDoesNotWhatItSays(): void
    {
        $app = $this->app(static function (Router $r): void {
            $r->get('/about', [WebsitePages::class, 'about']);
            $r->get('/me', [ProtectedController::class, 'me'])->middleware(AuthorizationMiddleware::class);
            $r->post('/articles', [TwoPermissions::class, 'store'])->middleware(AuthorizationMiddleware::class);
            $r->get('/report', [EditorController::class, 'edit']);   // nothing enforces its permission
            $r->get('/admin', [UndeclaredController::class, 'index']);
            $r->group('/manage', static fn (Router $r) => $r->get('', [UndeclaredController::class, 'index']), [ApiSessionRequired::class]);
            $r->get('/about', [WebsitePages::class, 'about']);   // the same route twice
        }, ['security.access_middleware' => [ApiSessionRequired::class => 'Sends visitors without an API session to sign in']]);

        $this->assertSame([
            'GET /about' => ['access' => 'public', 'reason' => 'The pages of the public website'],
            'GET /about (2)' => ['access' => 'public', 'reason' => 'The pages of the public website'],
            'GET /admin' => ['access' => 'anyone', 'problem' => 'It does not say who may reach it.'],
            'GET /manage' => ['access' => 'user', 'middleware' => ApiSessionRequired::class],
            'GET /me' => ['access' => 'user'],
            'GET /report' => ['access' => 'anyone', 'problem' => 'It requires a user, but AuthorizationMiddleware is not on the route.'],
            'POST /articles' => ['access' => 'permission', 'permissions' => ['articles.edit', 'articles.publish']],
        ], $this->byKey($this->exposure($app)->routes));
        $this->assertSame(
            ['GET /about', 'GET /about (2)', 'GET /admin', 'POST /articles', 'GET /manage', 'GET /me', 'GET /report'],
            array_keys($this->exposure($app)->routes),
            'sorted by path, then methods',
        );
    }

    public function testTheFileHasOneLineARouteAndReadsBackTheSame(): void
    {
        $exposure = $this->exposure($this->app(static function (Router $r): void {
            $r->get('/about', [WebsitePages::class, 'about']);
            $r->post('/articles', [TwoPermissions::class, 'store'])->middleware(AuthorizationMiddleware::class);
        }));
        $json = $exposure->encode();

        $this->assertStringContainsString("\n        \"GET /about\": {\"access\": \"public\", \"reason\": \"The pages of the public website\"},\n", $json);
        $this->assertStringContainsString('"POST /articles": {"access": "permission", "permissions": ["articles.edit","articles.publish"]}' . "\n", $json);
        $this->assertStringEndsWith("}\n", $json);
        $this->assertIsArray(json_decode($json, true), 'valid JSON');

        file_put_contents("{$this->base}/copy.json", $json);
        $this->assertSame([], $exposure->changesSince(Exposure::read("{$this->base}/copy.json")));
        unlink("{$this->base}/copy.json");
    }

    public function testWithoutAFileCheckWarnsOnceEvenInStrictMode(): void
    {
        $findings = $this->check($this->app(self::routes(...), strict: true));

        $this->assertCount(1, $findings);
        $this->assertSame('security.exposure', $findings[0]->id);
        $this->assertSame(Severity::Warning, $findings[0]->severity, 'a strict project that upgrades fails nothing (ADR-003)');
        $this->assertStringContainsString('security:exposure', (string) $findings[0]->hint);
        $this->assertTrue($findings[0]->security);
    }

    public function testAnUpToDateFileIsQuietWhateverItsLayout(): void
    {
        $app = $this->app(self::routes(...), strict: true);
        $this->write($app);
        $this->assertSame([], $this->check($app));

        // As git on Windows may check it out, and as a hand edit may order it.
        $data = json_decode((string) file_get_contents("{$this->base}/security/exposure.json"), true);
        assert(is_array($data) && is_array($data['routes']));
        $routes = array_map(static fn (array $entry): array => array_reverse($entry, true), array_reverse($data['routes'], true));
        file_put_contents("{$this->base}/security/exposure.json", str_replace("\n", "\r\n", (string) json_encode(['routes' => $routes], JSON_PRETTY_PRINT)));
        $this->assertCount(0, $this->check($app), 'reordered, with CRLF line endings');

        file_put_contents("{$this->base}/security/exposure.json", "\u{FEFF}" . $this->exposure($app)->encode());
        $this->assertCount(0, $this->check($app), 'with the byte order mark some Windows editors write');
    }

    public function testANewRouteIsReportedUntilTheFileIsWrittenAgain(): void
    {
        $this->write($this->app(self::routes(...)));
        $more = static function (Router $r): void {
            self::routes($r);
            $r->post('/contact', #[PublicRoute(reason: 'The contact form')] static fn (): string => 'thanks');
        };

        $findings = $this->check($this->app($more, strict: true));
        $this->assertCount(1, $findings);
        $this->assertSame(Severity::Error, $findings[0]->severity);
        $this->assertSame('POST /contact is new, and not yet in security/exposure.json: anyone (public: "The contact form") may reach it.', $findings[0]->message);
        $this->assertStringContainsString('ExposureTest.php:', (string) $findings[0]->file, 'it points at the handler');
        $this->assertSame(Severity::Warning, $this->check($this->app($more))[0]->severity, 'a warning unless strict');

        $this->write($this->app($more));
        $this->assertSame([], $this->check($this->app($more, strict: true)), 'reviewed');
    }

    public function testAChangeOfAccessIsReported(): void
    {
        $this->write($this->app(self::routes(...)));

        $findings = $this->check($this->app(static function (Router $r): void {
            $r->get('/about', [WebsitePages::class, 'about']);
            $r->get('/me', [ProtectedController::class, 'me']);   // AuthorizationMiddleware dropped
        }, strict: true));

        $this->assertCount(1, $findings);
        $this->assertSame(Severity::Error, $findings[0]->severity);
        $this->assertSame(
            'GET /me: who may reach it changed, from signed-in users to anyone (it requires a user, but AuthorizationMiddleware is not on the route), and security/exposure.json still records the former.',
            $findings[0]->message,
        );
    }

    public function testAPermissionAddedToARouteIsAChangeToo(): void
    {
        $this->write($this->app(static fn (Router $r) => $r->get('/me', [ProtectedController::class, 'me'])->middleware(AuthorizationMiddleware::class)));

        $findings = $this->check($this->app(static fn (Router $r) => $r->get('/me', [EditorController::class, 'edit'])->middleware(AuthorizationMiddleware::class), strict: true));

        $this->assertSame(['GET /me: who may reach it changed, from signed-in users to users with articles.edit, and security/exposure.json still records the former.'], array_map(static fn (Finding $f): string => $f->message, $findings));
    }

    public function testARouteThatIsGoneIsOnlyAWarning(): void
    {
        $this->write($this->app(self::routes(...)));

        $findings = $this->check($this->app(static fn (Router $r) => $r->get('/about', [WebsitePages::class, 'about']), strict: true));

        $this->assertCount(1, $findings);
        $this->assertSame(Severity::Warning, $findings[0]->severity, 'it exposes nothing');
        $this->assertSame('GET /me is in security/exposure.json, but the application has no such route any more.', $findings[0]->message);
    }

    public function testAFileThatIsNotAListFails(): void
    {
        foreach ([
            'not json' => 'it is not valid JSON',
            '{"about": "x"}' => 'it has no "routes" object',
            '{"routes": {"GET /me": {"reason": "x"}}}' => 'the entry "GET /me" has no "access"',
            '{"routes": {"GET /me": {"access": "user", "n": 1}}}' => 'neither text nor a list of text',
            '{"routes": ["GET /me"]}' => 'it has no "routes" object, of each route by its methods and path',
            '{"routes": {"1": {"access": "user"}}}' => 'the entry 1 is not named by its methods and path',
            str_repeat("\n", (2 << 20) + 1) => 'it is larger than 2 MB',   // check would run out of memory on a file of 20 MB
        ] as $contents => $problem) {
            @mkdir("{$this->base}/security");
            file_put_contents("{$this->base}/security/exposure.json", $contents);
            $findings = $this->check($this->app(self::routes(...), strict: true));

            $this->assertCount(1, $findings, $contents);
            $this->assertSame(Severity::Error, $findings[0]->severity, $contents);
            $this->assertStringContainsString($problem, $findings[0]->message, $contents);
        }
    }

    public function testNoRoutesNothingToSay(): void
    {
        $this->assertSame([], $this->check($this->app(static function (Router $r): void {
        }, strict: true)));
    }

    // ── security:exposure ──────────────────────────────────────────────────

    public function testTheCommandWritesTheFileAndSaysWhatChanged(): void
    {
        $first = $this->console($this->app(self::routes(...), console: true));
        $this->assertSame(0, $first[0]);
        $this->assertStringContainsString('Wrote security/exposure.json: 2 route(s), 1 public, 1 for signed-in users.', $first[1]);
        $this->assertFileExists("{$this->base}/security/exposure.json");

        $same = $this->console($this->app(self::routes(...), console: true));
        $this->assertStringContainsString('is up to date: 2 route(s), nothing changed', $same[1]);

        $changed = $this->console($this->app(static function (Router $r): void {
            $r->get('/me', [ProtectedController::class, 'me']);
            $r->get('/admin', [UndeclaredController::class, 'index']);
        }, console: true));
        $this->assertSame(0, $changed[0]);
        $this->assertStringContainsString('3 change(s)', $changed[1]);
        $this->assertStringContainsString('- GET /about', $changed[1]);
        $this->assertStringContainsString('+ GET /admin: anyone (it does not say who may reach it)', $changed[1]);
        $this->assertStringContainsString('~ GET /me: signed-in users → anyone (it requires a user', $changed[1]);
        $this->assertStringContainsString('2 route(s) can be reached by anyone without saying so', $changed[1]);
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    private static function routes(Router $r): void
    {
        $r->get('/about', [WebsitePages::class, 'about']);
        $r->get('/me', [ProtectedController::class, 'me'])->middleware(AuthorizationMiddleware::class);
    }

    /**
     * @param array<string, mixed> $config
     */
    private function app(\Closure $routes, array $config = [], bool $strict = false, bool $console = false): ApplicationInterface
    {
        $providers = [HttpServiceProvider::class, RoutingServiceProvider::class, SecurityServiceProvider::class];
        if ($console) {
            $providers[] = ConsoleServiceProvider::class;
        }
        $app = Application::configure($this->base)
            ->withEnvironment('testing')
            ->withConfiguration(['security.secret' => str_repeat('s', 40), 'security.strict' => $strict, ...$config])
            ->withProviders(...$providers)
            ->build();
        $router = $app->container()->get(Router::class);
        assert($router instanceof Router);
        $routes($router);

        return $app;
    }

    private function exposure(ApplicationInterface $app): Exposure
    {
        $router = $app->container()->get(Router::class);
        $config = $app->container()->get(ConfigurationInterface::class);
        assert($router instanceof Router && $config instanceof ConfigurationInterface);

        return Exposure::of($router, $config);
    }

    private function write(ApplicationInterface $app): void
    {
        @mkdir("{$this->base}/security");
        file_put_contents("{$this->base}/security/exposure.json", $this->exposure($app)->encode());
    }

    /**
     * @param array<string, mixed> $routes
     * @return array<string, mixed>
     */
    private function byKey(array $routes): array
    {
        ksort($routes);

        return $routes;
    }

    /**
     * @return list<Finding>
     */
    private function check(ApplicationInterface $app): array
    {
        foreach ($app->container()->tagged(ApplicationCheck::TAG) as $check) {
            if ($check instanceof ExposureCheck) {
                return $check->findings($app);
            }
        }
        self::fail('ExposureCheck is not tagged.');
    }

    /**
     * @return array{0: int, 1: string}
     */
    private function console(ApplicationInterface $app): array
    {
        $kernel = $app->container()->get(ConsoleKernel::class);
        assert($kernel instanceof ConsoleKernel);
        $console = $kernel->application();
        $console->setAutoExit(false);
        $tester = new ApplicationTester($console);
        $code = $tester->run(['command' => 'security:exposure']);

        return [$code, (string) preg_replace('/\s+/', ' ', $tester->getDisplay())];
    }
}

final class TwoPermissions
{
    #[RequiresPermission('articles.publish')]
    #[RequiresPermission('articles.edit')]
    public function store(): string
    {
        return 'stored';
    }
}
