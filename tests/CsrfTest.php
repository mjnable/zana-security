<?php

declare(strict_types=1);

namespace Zana\Security\Tests;

use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\SimpleCache\CacheInterface;
use Zana\Container\Contracts\ServiceCollectionInterface;
use Zana\Core\Application;
use Zana\Http\HttpKernel;
use Zana\Http\HttpServiceProvider;
use Zana\Routing\Router;
use Zana\Routing\RoutingServiceProvider;
use Zana\Security\Attribute\WithoutCsrf;
use Zana\Security\CsrfTokens;
use Zana\Security\Middleware\CsrfMiddleware;
use Zana\Security\SecurityException;
use Zana\Security\SecurityServiceProvider;
use Zana\Security\TokenSigner;

final class CsrfTest extends TestCase
{
    private const string SECRET = 'a-test-secret-that-is-long-enough-1234';

    private int $now = 1_800_000_000;

    public function testTokensAreBoundToTheirForm(): void
    {
        $tokens = new CsrfTokens($this->signer());
        $token = $tokens->issue('contact');

        $this->assertTrue($tokens->verify($token, 'contact'));
        $this->assertTrue($tokens->verify($token, 'contact'), 'reusable by default');
        $this->assertFalse($tokens->verify($token, 'newsletter'));
        $this->assertFalse($tokens->verify($token));
        $this->assertFalse($tokens->verify('garbage', 'contact'));
        $this->assertNotSame($token, $tokens->issue('contact'), 'each token has its own nonce');
    }

    public function testTokensExpire(): void
    {
        $tokens = new CsrfTokens($this->signer(), lifetime: 60);
        $token = $tokens->issue();

        $this->now += 61;
        $this->assertFalse($tokens->verify($token));
    }

    public function testSingleUseTokensNeedACache(): void
    {
        $tokens = new CsrfTokens($this->signer(), new ArrayCache(), singleUse: true);
        $token = $tokens->issue();

        $this->assertTrue($tokens->verify($token));
        $this->assertFalse($tokens->verify($token), 'a replay is refused');

        $this->expectException(SecurityException::class);
        new CsrfTokens($this->signer(), singleUse: true);
    }

    public function testFormPostsNeedAValidToken(): void
    {
        [$kernel, $tokens] = $this->app();

        $this->assertSame(403, $this->post($kernel, '/contact', [])->getStatusCode(), 'no token');
        $this->assertSame(403, $this->post($kernel, '/contact', ['_token' => 'forged'])->getStatusCode());
        $this->assertSame(403, $this->post($kernel, '/contact', ['_token' => $tokens->issue('other'), '_form' => 'contact'])->getStatusCode(), 'another form');
        $this->assertSame(200, $this->post($kernel, '/contact', ['_token' => $tokens->issue('contact'), '_form' => 'contact'])->getStatusCode());
        $this->assertSame(200, $this->post($kernel, '/contact', ['_token' => $tokens->issue()])->getStatusCode(), 'default form');
    }

    public function testTheTokenMayComeFromAHeader(): void
    {
        [$kernel, $tokens] = $this->app();

        $this->assertSame(200, $this->post($kernel, '/contact', [], ['X-CSRF-Token' => $tokens->issue()])->getStatusCode());
    }

    public function testCrossSiteRequestsAreRefusedEvenWithAToken(): void
    {
        [$kernel, $tokens] = $this->app();
        $fields = ['_token' => $tokens->issue()];

        $this->assertSame(403, $this->post($kernel, '/contact', $fields, ['Sec-Fetch-Site' => 'cross-site'])->getStatusCode());
        $this->assertSame(403, $this->post($kernel, '/contact', $fields, ['Origin' => 'https://evil.example'])->getStatusCode());
        $this->assertSame(200, $this->post($kernel, '/contact', $fields, ['Sec-Fetch-Site' => 'same-origin', 'Origin' => 'https://shop.example'])->getStatusCode());
    }

    public function testSafeMethodsApiCallsAndOptedOutHandlersAreNotChecked(): void
    {
        [$kernel] = $this->app();

        $this->assertSame(200, $kernel->handle(new ServerRequest('GET', 'https://shop.example/contact'))->getStatusCode());
        $this->assertSame(200, $this->post($kernel, '/contact', [], ['Authorization' => 'Bearer x'])->getStatusCode());
        $this->assertSame(200, $this->post($kernel, '/webhook', [])->getStatusCode());
    }

    /**
     * @return array{HttpKernel, CsrfTokens}
     */
    private function app(): array
    {
        $container = Application::configure(sys_get_temp_dir() . '/zana-security-csrf')
            ->withEnvironment('testing')
            ->withConfiguration(['security.secret' => self::SECRET])
            ->withProviders(HttpServiceProvider::class, RoutingServiceProvider::class, SecurityServiceProvider::class)
            ->withServices(static fn (ServiceCollectionInterface $s) => $s->transient(Webhook::class))
            ->build()
            ->container();

        $router = $container->get(Router::class);
        assert($router instanceof Router);
        $router->group('', static function (Router $r): void {
            $r->map(['GET', 'POST'], '/contact', static fn (): string => 'sent');
            $r->post('/webhook', Webhook::class);
        }, [CsrfMiddleware::class]);

        $kernel = $container->get(HttpKernel::class);
        $tokens = $container->get(CsrfTokens::class);
        assert($kernel instanceof HttpKernel && $tokens instanceof CsrfTokens);

        return [$kernel, $tokens];
    }

    /**
     * @param array<string, string> $fields
     * @param array<string, string> $headers
     */
    private function post(HttpKernel $kernel, string $path, array $fields, array $headers = []): ResponseInterface
    {
        $request = new ServerRequest('POST', 'https://shop.example' . $path, ['Accept' => 'application/json', ...$headers]);

        return $kernel->handle($request->withParsedBody($fields));
    }

    private function signer(): TokenSigner
    {
        return new TokenSigner(self::SECRET, fn (): int => $this->now);
    }
}

#[WithoutCsrf]
final class Webhook
{
    public function __invoke(): string
    {
        return 'received';
    }
}

final class ArrayCache implements CacheInterface
{
    /** @var array<string, mixed> */
    private array $items = [];

    public function get(string $key, mixed $default = null): mixed
    {
        return $this->items[$key] ?? $default;
    }

    public function set(string $key, mixed $value, \DateInterval|int|null $ttl = null): bool
    {
        $this->items[$key] = $value;

        return true;
    }

    public function delete(string $key): bool
    {
        unset($this->items[$key]);

        return true;
    }

    public function clear(): bool
    {
        $this->items = [];

        return true;
    }

    public function getMultiple(iterable $keys, mixed $default = null): iterable
    {
        foreach ($keys as $key) {
            yield $key => $this->get($key, $default);
        }
    }

    /**
     * @param iterable<string, mixed> $values
     */
    public function setMultiple(iterable $values, \DateInterval|int|null $ttl = null): bool
    {
        foreach ($values as $key => $value) {
            $this->set($key, $value);
        }

        return true;
    }

    public function deleteMultiple(iterable $keys): bool
    {
        foreach ($keys as $key) {
            $this->delete($key);
        }

        return true;
    }

    public function has(string $key): bool
    {
        return array_key_exists($key, $this->items);
    }
}
