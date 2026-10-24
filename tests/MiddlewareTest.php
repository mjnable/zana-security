<?php

declare(strict_types=1);

namespace Zana\Security\Tests;

use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\Attributes\After;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Zana\Container\Contracts\ContainerInterface;
use Zana\Container\Contracts\ServiceCollectionInterface;
use Zana\Core\Application;
use Zana\Http\HttpKernel;
use Zana\Http\HttpServiceProvider;
use Zana\Routing\Router;
use Zana\Routing\RoutingServiceProvider;
use Zana\Security\Attribute\RequiresPermission;
use Zana\Security\Authorizer;
use Zana\Security\Middleware\AuthenticationMiddleware;
use Zana\Security\Middleware\AuthorizationMiddleware;
use Zana\Security\PasswordHasher;
use Zana\Security\SecurityContext;
use Zana\Security\SecurityException;
use Zana\Security\SecurityServiceProvider;
use Zana\Security\TokenSigner;
use Zana\Security\UserProviderInterface;

final class MiddlewareTest extends TestCase
{
    private string $base = '';

    private ContainerInterface $container;

    private HttpKernel $kernel;

    private TokenSigner $signer;

    protected function setUp(): void
    {
        $this->base = sys_get_temp_dir() . '/zana-security-' . bin2hex(random_bytes(4));
        mkdir("{$this->base}/config", 0777, true);
        $this->config('security', "[
            'secret' => str_repeat('s', 40),
            'password_options' => ['memory_cost' => 8192, 'time_cost' => 1],
            'roles' => ['viewer' => ['reports.view'], 'clinician' => ['reports.export'], 'admin' => ['*']],
            'hierarchy' => ['clinician' => ['viewer']],
            'policies' => [\\Zana\\Security\\Tests\\MeasurementPolicy::class],
        ]");
        $this->config('http', "['middleware' => [\\Zana\\Security\\Middleware\\AuthenticationMiddleware::class]]");

        $this->container = $this->build(static fn (ServiceCollectionInterface $s) => $s
            ->singleton(UserProviderInterface::class, Users::class)
            ->transient(PublicController::class)
            ->transient(ProfileController::class)
            ->transient(ReportController::class));

        $router = $this->container->get(Router::class);
        $router->get('/public', PublicController::class)->middleware(AuthorizationMiddleware::class);
        $router->group('', static function (Router $r): void {
            $r->get('/profile', [ProfileController::class, 'show']);
            $r->get('/reports', [ReportController::class, 'index']);
            $r->get('/reports/export', [ReportController::class, 'export']);
            $r->get('/closure', #[RequiresPermission('reports.export')] static fn (): string => 'closure');
            $r->get('/whoami', static fn (ServerRequestInterface $request): string => 'user:' . ($request->getAttribute('user')?->identifier() ?? 'anonymous'));
        }, [AuthorizationMiddleware::class]);

        $this->kernel = $this->container->get(HttpKernel::class);
        $this->signer = $this->container->get(TokenSigner::class);
    }

    #[After]
    public function removeBase(): void
    {
        foreach (glob("{$this->base}/config/*") ?: [] as $file) {
            unlink($file);
        }
        @rmdir("{$this->base}/config");
        @rmdir($this->base);
    }

    public function testAnonymousRequestsPassThrough(): void
    {
        $this->assertResponse(200, 'public', $this->send('/public'));
        $this->assertResponse(200, 'user:anonymous', $this->send('/whoami'));
    }

    public function testBearerTokensAuthenticate(): void
    {
        $this->assertResponse(200, 'user:grace', $this->send('/whoami', 'grace'));
        $this->assertResponse(200, 'profile:grace', $this->send('/profile', 'grace'));
    }

    public function testBadCredentialsAreUnauthorized(): void
    {
        $expired = new TokenSigner(str_repeat('s', 40), static fn (): int => 1_000)->issue('grace', 60);

        foreach ([
            'Basic Z3JhY2U6c2VjcmV0' => 'must use the Bearer scheme',
            'Bearer' => 'must use the Bearer scheme',
            'Bearer not-a-token' => 'malformed',
            "Bearer {$expired}" => 'expired',
            'Bearer ' . $this->signer->issue('nobody', 60) => 'does not exist',
        ] as $header => $reason) {
            $response = $this->kernel->handle(new ServerRequest('GET', '/public', ['Authorization' => $header, 'Accept' => 'application/json']));
            $this->assertSame(401, $response->getStatusCode(), $header);
            $this->assertSame('Bearer', $response->getHeaderLine('WWW-Authenticate'), $header);
            $this->assertStringContainsString($reason, (string) $response->getBody(), $header);
        }
    }

    public function testRequiresAuthentication(): void
    {
        $this->assertSame(401, $this->send('/profile')->getStatusCode());
        $this->assertSame('Bearer', $this->send('/profile')->getHeaderLine('WWW-Authenticate'));
        $this->assertResponse(200, 'profile:alan', $this->send('/profile', 'alan'), 'any user, no permission needed');
    }

    public function testRequiresPermissionOnTheClassAndTheMethod(): void
    {
        $this->assertSame(401, $this->send('/reports')->getStatusCode(), 'a permission implies authentication');
        $this->assertSame(403, $this->send('/reports', 'alan')->getStatusCode());
        $this->assertResponse(200, 'reports', $this->send('/reports', 'grace'));
        $this->assertResponse(200, 'export', $this->send('/reports/export', 'grace'), 'class and method permissions');
        $this->assertResponse(200, 'export', $this->send('/reports/export', 'ada'), 'wildcard');

        $viewer = new User('vera', ['viewer']);
        $this->container->get(UserProviderInterface::class)->users['vera'] = $viewer;
        $this->assertSame(403, $this->send('/reports/export', 'vera')->getStatusCode(), 'the method permission is also required');
        $this->assertSame(403, $this->send('/closure', 'vera')->getStatusCode(), 'closure handlers are checked too');
        $this->assertResponse(200, 'closure', $this->send('/closure', 'grace'));
    }

    public function testTheProviderWiring(): void
    {
        $scope = $this->container->createScope();
        $this->assertNotSame($scope->get(SecurityContext::class), $this->container->createScope()->get(SecurityContext::class), 'scoped');
        $this->assertInstanceOf(AuthenticationMiddleware::class, $scope->get(AuthenticationMiddleware::class));

        $hasher = $this->container->get(PasswordHasher::class);
        $this->assertFalse($hasher->needsRehash(password_hash('x', PASSWORD_ARGON2ID, ['memory_cost' => 8192, 'time_cost' => 1])), 'configured options');
        $this->assertTrue($this->container->get(Authorizer::class)->can(new User('g'), 'measurements.edit', new Measurement('g')), 'configured policy');
    }

    public function testTheSecretIsRequiredWhenTheSignerIsResolved(): void
    {
        unlink("{$this->base}/config/security.php");
        $container = $this->build(static fn (ServiceCollectionInterface $s) => $s);

        $this->assertInstanceOf(Authorizer::class, $container->get(Authorizer::class));

        try {
            $container->get(TokenSigner::class);
            $this->fail('The signer needs a secret.');
        } catch (\Throwable $e) {
            $cause = $e->getPrevious() ?? $e;
            $this->assertInstanceOf(SecurityException::class, $cause, 'the container wraps the factory exception');
            $this->assertStringContainsString('Set security.secret', $cause->getMessage());
        }
    }

    private function config(string $name, string $php): void
    {
        file_put_contents("{$this->base}/config/{$name}.php", "<?php return {$php};");
    }

    /**
     * @param \Closure(ServiceCollectionInterface): mixed $services
     */
    private function build(\Closure $services): ContainerInterface
    {
        return Application::configure($this->base)
            ->withProviders(HttpServiceProvider::class, RoutingServiceProvider::class, SecurityServiceProvider::class)
            ->withServices($services)
            ->build()
            ->container();
    }

    private function send(string $path, ?string $user = null): ResponseInterface
    {
        $headers = ['Accept' => 'application/json'];
        if ($user !== null) {
            $headers['Authorization'] = 'Bearer ' . $this->signer->issue($user, 300);
        }

        return $this->kernel->handle(new ServerRequest('GET', $path, $headers));
    }

    private function assertResponse(int $status, string $body, ResponseInterface $response, string $message = ''): void
    {
        $this->assertSame($status, $response->getStatusCode(), $message . ' ' . $response->getBody());
        $this->assertSame($body, (string) $response->getBody(), $message);
    }
}
