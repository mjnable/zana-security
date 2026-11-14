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
 * 2.23, FE-68 layer 4, ADR-033: security/exposure.json is the reviewed
 * baseline of who may reach each route. check compares the routes with it
 * and never writes it; security:exposure shows what changed and writes
 * nothing; only --init and --update record it.
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
        @unlink($this->file());
        @rmdir("{$this->base}/security");
        @rmdir($this->base);
    }

    // ── What is recorded ───────────────────────────────────────────────────

    public function testEachRouteIsRecordedAsWhatItDoesNotWhatItSays(): void
    {
        $app = $this->app(static function (Router $r): void {
            $r->get('/about', [WebsitePages::class, 'about']);
            $r->get('/me', [ProtectedController::class, 'me'])->middleware(AuthorizationMiddleware::class);
            $r->post('/articles', [TwoPermissions::class, 'edit'])->middleware(AuthorizationMiddleware::class);
            $r->get('/report', [ArticleEditor::class, 'edit']);   // nothing enforces its permission
            $r->get('/admin', [UndeclaredController::class, 'index']);
            $r->group('/manage', static fn (Router $r) => $r->get('', [UndeclaredController::class, 'index']), [ApiSessionRequired::class]);
            $r->get('/about', [WebsitePages::class, 'about']);   // the same route twice
        }, ['security.access_middleware' => [ApiSessionRequired::class => 'Sends visitors without an API session to sign in']]);

        $routes = $this->exposure($app)->routes;
        $this->assertSame([
            'GET /about' => ['access' => 'public', 'reason' => 'The pages of the public website'],
            'GET /about (2)' => ['access' => 'public', 'reason' => 'The pages of the public website'],
            'GET /admin' => ['access' => 'anyone', 'problem' => 'It does not say who may reach it.'],
            'POST /articles' => ['access' => 'permission', 'permissions' => ['articles.edit', 'articles.publish']],
            'GET /manage' => ['access' => 'user', 'middleware' => ApiSessionRequired::class],
            'GET /me' => ['access' => 'user'],
            'GET /report' => ['access' => 'anyone', 'problem' => 'It requires a user, but AuthorizationMiddleware is not on the route.'],
        ], $routes, 'sorted by path, then methods');
    }

    public function testADeclaredPublicRouteIsNotAnOpenOne(): void
    {
        $routes = $this->exposure($this->app(static function (Router $r): void {
            $r->get('/about', [WebsitePages::class, 'about']);
            $r->get('/admin', [UndeclaredController::class, 'index']);
        }))->routes;

        $this->assertSame('public', $routes['GET /about']['access'], 'anyone may reach it, and it says why');
        $this->assertSame('anyone', $routes['GET /admin']['access'], 'anyone may reach it, and nothing says so');
        $this->assertArrayNotHasKey('reason', $routes['GET /admin']);
        $this->assertSame('anyone (public: "The pages of the public website")', Exposure::describe($routes['GET /about']));
        $this->assertSame('anyone (it does not say who may reach it)', Exposure::describe($routes['GET /admin']));

        // Either way round is a change.
        $this->baseline(static fn (Router $r) => $r->get('/page', [WebsitePages::class, 'about']));
        $this->assertSame(
            ['GET /page: who may reach it changed, from anyone (public: "The pages of the public website") to anyone (it does not say who may reach it), and the reviewed baseline security/exposure.json still records the former.'],
            self::messages($this->check($this->app(static fn (Router $r) => $r->get('/page', [UndeclaredController::class, 'index']), strict: true))),
        );
        $this->baseline(static fn (Router $r) => $r->get('/page', [UndeclaredController::class, 'index']));
        $this->assertCount(1, $this->check($this->app(static fn (Router $r) => $r->get('/page', [WebsitePages::class, 'about']), strict: true)));
    }

    // ── Deterministic ──────────────────────────────────────────────────────

    public function testTheFileIsTheSameWhateverTheOrderTheEnvironmentOrTheMachine(): void
    {
        $forward = static function (Router $r): void {
            $r->get('/about', [WebsitePages::class, 'about']);
            $r->post('/articles', [TwoPermissions::class, 'edit'])->middleware(AuthorizationMiddleware::class);
            $r->get('/me', [ProtectedController::class, 'me'])->middleware(AuthorizationMiddleware::class);
        };
        $backward = static function (Router $r): void {
            $r->get('/me', [ProtectedController::class, 'me'])->middleware(AuthorizationMiddleware::class);
            $r->post('/articles', [TwoPermissionsReversed::class, 'edit'])->middleware(AuthorizationMiddleware::class);   // its attributes the other way round
            $r->get('/about', [WebsitePages::class, 'about']);
        };

        $json = $this->exposure($this->app($forward))->encode();
        $this->assertSame($json, $this->exposure($this->app($backward))->encode(), 'routes and permissions in another order');
        $this->assertSame($json, $this->exposure($this->app($forward, environment: 'production'))->encode(), 'another environment');
        $this->assertSame($json, $this->exposure($this->app($forward, ['app.name' => 'Staging', 'security.strict' => true]))->encode(), 'other settings');
        $this->assertStringNotContainsString(basename($this->base), $json, 'no path of this machine');
        $this->assertStringNotContainsString(str_replace('\\', '/', sys_get_temp_dir()), str_replace('\\', '/', $json));
        $this->assertStringNotContainsString('.php', $json, 'no handler file');
        $this->assertDoesNotMatchRegularExpression('/20\d\d-\d\d-\d\d/', $json, 'no date');
    }

    public function testTheFileHasOneLineARouteAndReadsBackTheSame(): void
    {
        $exposure = $this->exposure($this->app(static function (Router $r): void {
            $r->get('/about', [WebsitePages::class, 'about']);
            $r->post('/articles', [TwoPermissions::class, 'edit'])->middleware(AuthorizationMiddleware::class);
        }));
        $json = $exposure->encode();

        $this->assertStringContainsString("\n        \"GET /about\": {\"access\": \"public\", \"reason\": \"The pages of the public website\"},\n", $json);
        $this->assertStringContainsString('"POST /articles": {"access": "permission", "permissions": ["articles.edit","articles.publish"]}' . "\n", $json);
        $this->assertStringEndsWith("}\n", $json);

        $this->put($json);
        $read = Exposure::read($this->file());
        $this->assertTrue($read->asWritten);
        $this->assertSame([], $exposure->changesSince($read));
    }

    // ── Access changes, also on routes that stay protected ─────────────────

    public function testANewRouteIsReportedUntilItIsRecorded(): void
    {
        $this->baseline(self::routes(...));
        $more = static function (Router $r): void {
            self::routes($r);
            $r->post('/contact', #[PublicRoute(reason: 'The contact form')] static fn (): string => 'thanks');
        };

        $findings = $this->check($this->app($more, strict: true));
        $this->assertCount(1, $findings);
        $this->assertSame(Severity::Error, $findings[0]->severity);
        $this->assertSame('POST /contact is new, and not in the reviewed baseline security/exposure.json: anyone (public: "The contact form") may reach it.', $findings[0]->message);
        $this->assertStringContainsString('security:exposure --update', (string) $findings[0]->hint);
        $this->assertStringContainsString('ExposureTest.php:', (string) $findings[0]->file, 'it points at the handler');
        $this->assertTrue($findings[0]->security, 'release:build stops on it in strict mode');
        $this->assertSame(Severity::Warning, $this->check($this->app($more))[0]->severity, 'a warning unless strict');

        $this->baseline($more);
        $this->assertSame([], $this->check($this->app($more, strict: true)), 'recorded');
    }

    public function testAProtectionRemovedIsReported(): void
    {
        $this->baseline(self::routes(...));

        $findings = $this->check($this->app(static function (Router $r): void {
            $r->get('/about', [WebsitePages::class, 'about']);
            $r->get('/me', [ProtectedController::class, 'me']);   // AuthorizationMiddleware dropped
        }, strict: true));

        $this->assertSame(
            ['GET /me: who may reach it changed, from signed-in users to anyone (it requires a user, but AuthorizationMiddleware is not on the route), and the reviewed baseline security/exposure.json still records the former.'],
            self::messages($findings),
        );
        $this->assertSame(Severity::Error, $findings[0]->severity);
    }

    /**
     * @return iterable<string, array{0: class-string, 1: class-string, 2: string}>
     */
    public static function permissionChanges(): iterable
    {
        yield 'a user, then a permission' => [ProtectedController::class, ArticleEditor::class, 'from signed-in users to users with articles.edit'];
        yield 'a permission, then only a user' => [ArticleEditor::class, ProtectedController::class, 'from users with articles.edit to signed-in users'];
        yield 'one permission for another' => [ArticleEditor::class, PublisherController::class, 'from users with articles.edit to users with articles.publish'];
        yield 'a second permission added' => [ArticleEditor::class, TwoPermissions::class, 'from users with articles.edit to users with articles.edit and articles.publish'];
        yield 'one of two dropped' => [TwoPermissions::class, PublisherController::class, 'from users with articles.edit and articles.publish to users with articles.publish'];
    }

    /**
     * @param class-string $before
     * @param class-string $after
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('permissionChanges')]
    public function testAChangeOfPermissionIsReportedWhileTheRouteStaysProtected(string $before, string $after, string $change): void
    {
        $route = self::articleRoute(...);
        $this->baseline($route($before));

        $findings = $this->check($this->app($route($after), strict: true));

        $this->assertCount(1, $findings);
        $this->assertSame(Severity::Error, $findings[0]->severity);
        $this->assertStringContainsString("POST /articles: who may reach it changed, {$change},", $findings[0]->message);
    }

    public function testAnotherSignInMiddlewareIsAChange(): void
    {
        $config = ['security.access_middleware' => [ApiSessionRequired::class => 'Sends visitors to sign in', OtherSignIn::class => 'Sends visitors to the other sign-in']];
        $routes = self::manageRoute(...);
        $this->baseline($routes(ApiSessionRequired::class), $config);

        $this->assertSame(
            ['GET /manage: who may reach it changed, from signed-in users (by ' . ApiSessionRequired::class . ') to signed-in users (by ' . OtherSignIn::class . '), and the reviewed baseline security/exposure.json still records the former.'],
            self::messages($this->check($this->app($routes(OtherSignIn::class), $config, strict: true))),
        );
    }

    public function testARouteThatIsGoneIsOnlyAWarning(): void
    {
        $this->baseline(self::routes(...));

        $findings = $this->check($this->app(static fn (Router $r) => $r->get('/about', [WebsitePages::class, 'about']), strict: true));

        $this->assertSame(['GET /me is in security/exposure.json, but the application has no such route any more.'], self::messages($findings));
        $this->assertSame(Severity::Warning, $findings[0]->severity, 'it exposes nothing');
    }

    // ── The baseline: missing, broken, edited ──────────────────────────────

    public function testWithoutABaselineCheckWarnsOnceEvenInStrictMode(): void
    {
        $findings = $this->check($this->app(self::routes(...), strict: true));

        $this->assertCount(1, $findings);
        $this->assertSame('security.exposure', $findings[0]->id);
        $this->assertSame(Severity::Warning, $findings[0]->severity, 'a strict project that upgrades fails nothing (ADR-003)');
        $this->assertStringContainsString('--init', (string) $findings[0]->hint);
    }

    public function testWhatGitAndEditorsChangeIsAccepted(): void
    {
        $app = $this->app(self::routes(...), strict: true);
        $json = $this->exposure($app)->encode();

        $this->put(str_replace("\n", "\r\n", $json));
        $this->assertSame([], $this->check($app), 'CRLF, as Git on Windows checks it out');
        $this->put("\u{FEFF}" . $json);
        $this->assertCount(0, $this->check($app), 'the byte order mark some Windows editors write');
    }

    /**
     * @return iterable<string, array{0: \Closure(string): string}>
     */
    public static function handEdits(): iterable
    {
        yield 'reordered' => [static fn (string $json): string => (string) preg_replace_callback('/("GET \/about".*?),\n(\s+"GET \/me".*?)\n/', static fn (array $m): string => "{$m[2]},\n" . ltrim($m[1]) . "\n", $json)];
        yield 'reformatted' => [static fn (string $json): string => (string) json_encode(json_decode($json, true), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)];
        // json_decode keeps the last of two keys: an entry that looks reviewed could hide behind another.
        yield 'a route named twice' => [static fn (string $json): string => str_replace('"GET /me": {"access": "user"}', '"GET /me": {"access": "anyone", "problem": "x"},' . "\n" . '        "GET /me": {"access": "user"}', $json)];
        yield 'the about text removed' => [static fn (string $json): string => (string) preg_replace('/\n    "about": .*\n/', "\n", $json)];
    }

    /**
     * @param \Closure(string): string $edit
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('handEdits')]
    public function testABaselineEditedByHandFailsEvenWhenItMatches(\Closure $edit): void
    {
        $app = $this->app(self::routes(...), strict: true);
        $json = $this->exposure($app)->encode();
        $edited = $edit($json);
        $this->assertNotSame($json, $edited, 'the edit changed the file');
        $this->put($edited);

        $findings = $this->check($app);

        $this->assertSame(['security.exposure'], array_column(array_map(static fn (Finding $f): array => ['id' => $f->id], $findings), 'id'));
        $this->assertSame(Severity::Error, $findings[0]->severity);
        $this->assertStringContainsString('is not as security:exposure writes it', $findings[0]->message);
    }

    /**
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function brokenBaselines(): iterable
    {
        $routes = static fn (string $routes): string => '{"format": 1, "routes": {' . $routes . '}}';
        yield 'not JSON' => ['not json', 'it is not valid JSON'];
        yield 'no routes' => ['{"format": 1}', 'it has no "routes" object'];
        yield 'a list of routes' => ['{"format": 1, "routes": ["GET /me"]}', 'it has no "routes" object, of each route by its methods and path'];
        yield 'no format' => ['{"routes": {}}', 'its "format" is not 1'];
        yield 'a later format' => ['{"format": 2, "routes": {}}', 'its "format" is not 1'];
        yield 'a numeric key' => [$routes('"1": {"access": "user"}'), 'the entry 1 is not named by its methods and path'];
        yield 'no access' => [$routes('"GET /me": {"reason": "x"}'), 'the entry "GET /me" has no "access"'];
        yield 'an unknown access' => [$routes('"GET /me": {"access": "admin"}'), 'the access "admin", which is none of public, user, permission, anyone'];
        yield 'public without its reason' => [$routes('"GET /me": {"access": "public"}'), 'is "public" without its "reason"'];
        yield 'public with an empty reason' => [$routes('"GET /me": {"access": "public", "reason": " "}'), 'has "reason" that is not text'];
        yield 'a permission without permissions' => [$routes('"GET /me": {"access": "permission", "permissions": []}'), 'has "permissions" that is not a list of names'];
        yield 'a field another access has' => [$routes('"GET /me": {"access": "user", "reason": "x"}'), 'has a field "reason" that "user" does not have'];
        yield 'an unknown field' => [$routes('"GET /me": {"access": "user", "reviewed": "yes"}'), 'has a field "reviewed" that "user" does not have'];
        yield 'a number' => [$routes('"GET /me": {"access": "anyone", "problem": 1}'), 'has "problem" that is not text'];
        yield 'larger than 2 MB' => [str_repeat("\n", (2 << 20) + 1), 'it is larger than 2 MB'];   // 20 MB ran check out of memory
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('brokenBaselines')]
    public function testABrokenBaselineFails(string $contents, string $problem): void
    {
        $this->put($contents);

        $findings = $this->check($this->app(self::routes(...), strict: true));

        $this->assertCount(1, $findings);
        $this->assertSame(Severity::Error, $findings[0]->severity);
        $this->assertStringContainsString($problem, $findings[0]->message);
    }

    public function testCheckNeverWritesTheBaseline(): void
    {
        $this->check($this->app(self::routes(...), strict: true));
        $this->assertFileDoesNotExist($this->file(), 'not created when missing');

        $this->baseline(static fn (Router $r) => $r->get('/about', [WebsitePages::class, 'about']));
        $before = (string) file_get_contents($this->file());
        touch($this->file(), 1_000_000_000);
        clearstatcache();

        $this->assertCount(1, $this->check($this->app(self::routes(...), strict: true)), 'GET /me is new');
        clearstatcache();
        $this->assertSame($before, file_get_contents($this->file()), 'not updated when routes changed');
        $this->assertSame(1_000_000_000, filemtime($this->file()));
    }

    public function testNoRoutesNothingToSay(): void
    {
        $this->assertSame([], $this->check($this->app(static function (Router $r): void {
        }, strict: true)));
    }

    // ── security:exposure: showing and recording are apart ─────────────────

    public function testShowingWritesNothingAndFailsUntilTheBaselineIsRecorded(): void
    {
        [$code, $output] = $this->console(self::routes(...));

        $this->assertSame(1, $code, 'something to review');
        $this->assertFileDoesNotExist($this->file());
        $this->assertStringContainsString('There is no reviewed baseline yet', $output);
        $this->assertStringContainsString('GET /me: signed-in users', $output);
        $this->assertStringContainsString('Nothing was written', $output);
        $this->assertStringContainsString('--init', $output);
    }

    public function testInitRecordsTheFirstBaselineOnly(): void
    {
        [$code, $output] = $this->console(self::routes(...), '--init');
        $this->assertSame(0, $code);
        $this->assertStringContainsString('Recorded the first baseline, security/exposure.json: 2 route(s), 1 public, 1 for signed-in users.', $output);
        $this->assertSame([], $this->check($this->app(self::routes(...), strict: true)));

        $before = (string) file_get_contents($this->file());
        [$again, $refused] = $this->console(self::moreRoutes(...), '--init');
        $this->assertSame(1, $again, '--init never replaces a baseline');
        $this->assertStringContainsString('exists', $refused);
        $this->assertSame($before, file_get_contents($this->file()));
    }

    public function testRunningTheCommandAgainNeverApprovesAChange(): void
    {
        $this->baseline(self::routes(...));
        $before = (string) file_get_contents($this->file());

        for ($run = 1; $run <= 3; $run++) {
            [$code, $output] = $this->console(self::moreRoutes(...));
            $this->assertSame(1, $code, "run {$run}");
            $this->assertStringContainsString('2 route(s) differ from the reviewed baseline', $output);
            $this->assertStringContainsString('+ GET /admin: anyone (it does not say who may reach it)', $output);
            $this->assertStringContainsString('~ GET /me: signed-in users → users with articles.edit', $output);
            $this->assertStringContainsString('Nothing was written', $output);
        }

        $this->assertSame($before, file_get_contents($this->file()), 'the baseline is as it was');
        $this->assertCount(2, $this->check($this->app(self::moreRoutes(...), strict: true)), 'and check still fails');
    }

    public function testUpdateRecordsTheReviewedChangesAndListsEachOne(): void
    {
        $this->baseline(self::routes(...));

        [$code, $output] = $this->console(self::moreRoutes(...), '--update');

        $this->assertSame(0, $code);
        $this->assertStringContainsString('Recorded 2 change(s) in security/exposure.json:', $output);
        $this->assertStringContainsString('+ GET /admin: anyone (it does not say who may reach it)', $output);
        $this->assertStringContainsString('~ GET /me: signed-in users → users with articles.edit', $output);
        $this->assertStringContainsString('1 route(s) can be reached by anyone without saying so', $output);
        $this->assertSame([], $this->check($this->app(self::moreRoutes(...), strict: true)), 'the baseline now records them');

        [$same, $nothing] = $this->console(self::moreRoutes(...), '--update');
        $this->assertSame(0, $same);
        $this->assertStringContainsString('Nothing to record', $nothing);
        [$shown, $matches] = $this->console(self::moreRoutes(...));
        $this->assertSame(0, $shown);
        $this->assertStringContainsString('Every route matches the reviewed baseline', $matches);
    }

    public function testUpdateNeedsAReadableBaseline(): void
    {
        [$none, $output] = $this->console(self::routes(...), '--update');
        $this->assertSame(1, $none);
        $this->assertStringContainsString('There is no baseline to update', $output);
        $this->assertFileDoesNotExist($this->file());

        $this->put('{"format": 1, "routes": {"GET /me": {"access": "admin"}}}');
        [$broken, $refused] = $this->console(self::routes(...), '--update');
        $this->assertSame(1, $broken, 'replacing it would record every route unreviewed');
        $this->assertStringContainsString('Nothing was written', $refused);
        $this->assertSame('{"format": 1, "routes": {"GET /me": {"access": "admin"}}}', file_get_contents($this->file()));

        [$both] = $this->console(self::routes(...), '--init', '--update');
        $this->assertSame(1, $both);
    }

    public function testUpdateRewritesAHandEditedBaseline(): void
    {
        $app = $this->app(self::routes(...));
        $this->put((string) json_encode(json_decode($this->exposure($app)->encode(), true), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));

        [$shown, $warned] = $this->console(self::routes(...));
        $this->assertSame(1, $shown, 'shown, and not accepted as it is');
        $this->assertStringContainsString('edited by hand', $warned);

        [$code, $output] = $this->console(self::routes(...), '--update');
        $this->assertSame(0, $code);
        $this->assertStringContainsString('Rewrote security/exposure.json as the command writes it; no route changed.', $output);
        $this->assertSame([], $this->check($this->app(self::routes(...), strict: true)));
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    private static function routes(Router $r): void
    {
        $r->get('/about', [WebsitePages::class, 'about']);
        $r->get('/me', [ProtectedController::class, 'me'])->middleware(AuthorizationMiddleware::class);
    }

    /**
     * POST /articles, handled by a fixture class.
     *
     * @param class-string $class
     */
    private static function articleRoute(string $class): \Closure
    {
        return static fn (Router $r) => $r->post('/articles', [$class, $class === ProtectedController::class ? 'me' : 'edit'])->middleware(AuthorizationMiddleware::class);
    }

    /**
     * GET /manage behind a sign-in middleware of the application.
     *
     * @param class-string<\Psr\Http\Server\MiddlewareInterface> $middleware
     */
    private static function manageRoute(string $middleware): \Closure
    {
        return static fn (Router $r) => $r->get('/manage', [UndeclaredController::class, 'index'])->middleware($middleware);
    }

    /** A new open route, and /me now needs a permission. */
    private static function moreRoutes(Router $r): void
    {
        $r->get('/about', [WebsitePages::class, 'about']);
        $r->get('/me', [ArticleEditor::class, 'edit'])->middleware(AuthorizationMiddleware::class);
        $r->get('/admin', [UndeclaredController::class, 'index']);
    }

    /**
     * @param array<string, mixed> $config
     */
    private function app(\Closure $routes, array $config = [], bool $strict = false, bool $console = false, string $environment = 'testing'): ApplicationInterface
    {
        $providers = [HttpServiceProvider::class, RoutingServiceProvider::class, SecurityServiceProvider::class];
        if ($console) {
            $providers[] = ConsoleServiceProvider::class;
        }
        $app = Application::configure($this->base)
            ->withEnvironment($environment)
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

    private function file(): string
    {
        return "{$this->base}/security/exposure.json";
    }

    private function put(string $contents): void
    {
        @mkdir("{$this->base}/security");
        file_put_contents($this->file(), $contents);
    }

    /**
     * Records a baseline, as security:exposure --init or --update would.
     *
     * @param array<string, mixed> $config
     */
    private function baseline(\Closure $routes, array $config = []): void
    {
        $this->put($this->exposure($this->app($routes, $config))->encode());
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
     * @param list<Finding> $findings
     * @return list<string>
     */
    private static function messages(array $findings): array
    {
        return array_map(static fn (Finding $f): string => $f->message, $findings);
    }

    /**
     * @return array{0: int, 1: string}
     */
    private function console(\Closure $routes, string ...$options): array
    {
        $kernel = $this->app($routes, console: true)->container()->get(ConsoleKernel::class);
        assert($kernel instanceof ConsoleKernel);
        $console = $kernel->application();
        $console->setAutoExit(false);
        $tester = new ApplicationTester($console);
        $code = $tester->run(['command' => 'security:exposure', ...array_fill_keys($options, true)]);

        return [$code, (string) preg_replace('/\s+/', ' ', $tester->getDisplay())];
    }
}

final class TwoPermissions
{
    #[RequiresPermission('articles.publish')]
    #[RequiresPermission('articles.edit')]
    public function edit(): string
    {
        return 'stored';
    }
}

final class TwoPermissionsReversed
{
    #[RequiresPermission('articles.edit')]
    #[RequiresPermission('articles.publish')]
    public function edit(): string
    {
        return 'stored';
    }
}

final class PublisherController
{
    #[RequiresPermission('articles.publish')]
    public function edit(): string
    {
        return 'published';
    }
}

final class OtherSignIn implements \Psr\Http\Server\MiddlewareInterface
{
    public function process(\Psr\Http\Message\ServerRequestInterface $request, \Psr\Http\Server\RequestHandlerInterface $handler): \Psr\Http\Message\ResponseInterface
    {
        return $handler->handle($request);
    }
}

final class ArticleEditor
{
    #[RequiresPermission('articles.edit')]
    public function edit(): string
    {
        return 'edited';
    }
}
