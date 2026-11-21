<?php

declare(strict_types=1);

namespace Zana\Security\Tests;

use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;
use Zana\Cache\CacheServiceProvider;
use Zana\Container\Contracts\ServiceCollectionInterface;
use Zana\Core\Application;
use Zana\Security\SecurityServiceProvider;
use Zana\Session\SessionServiceProvider;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Zana\Http\Exception\TooManyRequestsHttpException;
use Zana\Http\Exception\UnauthorizedHttpException;
use Zana\Security\Attribute\RateLimit;
use Zana\Security\CsrfTokens;
use Zana\Security\Middleware\CsrfMiddleware;
use Zana\Security\Middleware\RateLimitMiddleware;
use Zana\Security\PasswordHasher;
use Zana\Security\PasswordResetTokens;
use Zana\Security\PasswordUpgraderInterface;
use Zana\Security\PasswordUserProviderInterface;
use Zana\Security\RateLimit\RateLimiter;
use Zana\Security\SecurityContext;
use Zana\Security\Session\SessionAuthenticationMiddleware;
use Zana\Security\Session\KnownDevice;
use Zana\Security\Session\KnownDeviceMiddleware;
use Zana\Security\Session\SessionLogin;
use Zana\Security\TokenSigner;
use Zana\Security\UserInterface;
use Zana\Session\Session;
use Zana\Session\SessionContext;

final class WebsiteSecurityTest extends TestCase
{
    private int $now = 1_800_000_000;

    // ── FE-10 rate limiting ────────────────────────────────────────────────

    public function testFixedWindows(): void
    {
        $limiter = $this->limiter();

        $results = array_map(static fn (): bool => $limiter->attempt('k', 3, 60)->allowed, range(1, 4));
        $this->assertSame([true, true, true, false], $results);

        $refused = $limiter->attempt('k', 3, 60);
        $this->assertSame([0, 60 - ($this->now % 60)], [$refused->remaining, $refused->resetAfter]);

        $this->now += 60;
        $this->assertTrue($limiter->attempt('k', 3, 60)->allowed, 'a new window');
        $this->assertTrue($limiter->attempt('other', 3, 60)->allowed, 'keys are separate');
    }

    public function testSlidingWindowsSmoothTheEdge(): void
    {
        $this->now = 1_800_000_000 - (1_800_000_000 % 60) + 50;   // late in a window
        $limiter = $this->limiter();
        foreach (range(1, 3) as $attempt) {
            $limiter->attempt('k', 3, 60, 'sliding');
        }

        $this->now += 15;   // 5 s into the next window: most of the previous one still counts
        $this->assertFalse($limiter->attempt('k', 3, 60, 'sliding')->allowed);
        $this->assertTrue($this->limiter()->attempt('k2', 3, 60, 'fixed')->allowed);

        $this->now += 50;   // almost all of the previous window has slid out
        $this->assertTrue($limiter->attempt('k', 3, 60, 'sliding')->allowed);
    }

    public function testTheMiddlewareLimitsPerClientAndAddsHeaders(): void
    {
        $middleware = new RateLimitMiddleware($this->limiter());
        $request = static fn (string $ip): ServerRequest => (new ServerRequest('POST', '/contact', serverParams: ['REMOTE_ADDR' => $ip]))
            ->withAttribute('_handler', [LimitedController::class, 'send']);

        $first = $middleware->process($request('198.51.100.1'), new PassThrough());
        $this->assertSame(['2', '1'], [$first->getHeaderLine('RateLimit-Limit'), $first->getHeaderLine('RateLimit-Remaining')]);
        $middleware->process($request('198.51.100.1'), new PassThrough());

        try {
            $middleware->process($request('198.51.100.1'), new PassThrough());
            $this->fail('Expected a 429.');
        } catch (TooManyRequestsHttpException $e) {
            $this->assertSame(429, $e->status);
            $this->assertArrayHasKey('Retry-After', $e->headers);
        }

        $this->assertSame(200, $middleware->process($request('198.51.100.2')->withAttribute('client_ip', '203.0.113.5'), new PassThrough())->getStatusCode(), 'another client');
        $this->assertFalse($middleware->process($request('198.51.100.1')->withAttribute('_handler', [LimitedController::class, 'free']), new PassThrough())->hasHeader('RateLimit-Limit'), 'unlimited handlers');
    }

    // ── FE-22 anti-spam ────────────────────────────────────────────────────

    public function testHoneypotsAndTooQuickPostsAreSpam(): void
    {
        $tokens = new CsrfTokens($this->signer(), minimumAge: 3, honeypot: 'website', clock: fn (): int => $this->now);
        $token = $tokens->issue();
        $post = static fn (array $fields): ServerRequest => (new ServerRequest('POST', 'https://example.com/contact'))->withParsedBody($fields);

        $silent = new CsrfMiddleware($tokens, spamRedirect: '/thanks');
        $this->assertSame('/thanks', $silent->process($post(['_token' => $token]), new PassThrough())->getHeaderLine('Location'), 'too quick');

        $this->now += 5;
        $this->assertSame('/thanks', $silent->process($post(['_token' => $token, 'website' => 'http://spam.example']), new PassThrough())->getHeaderLine('Location'), 'honeypot');
        $this->assertSame(200, $silent->process($post(['_token' => $token, 'website' => '']), new PassThrough())->getStatusCode());

        $this->expectExceptionMessage('The form could not be accepted.');
        (new CsrfMiddleware($tokens))->process($post(['_token' => $token, 'website' => 'x']), new PassThrough());
    }

    // ── FE-28 session login ────────────────────────────────────────────────

    public function testLoginRegeneratesTheSessionAndRemembersTheUser(): void
    {
        [$login, $session, $context] = $this->login();

        $this->assertNull($login->attempt('ada@example.com', 'wrong'));
        $this->assertNull($login->attempt('nobody@example.com', 'secret-pass'), 'unknown users fail the same way');

        $user = $login->attempt('ADA@example.com ', 'secret-pass');
        $this->assertSame('1', $user?->identifier());
        $this->assertSame('1', $session->get(SessionLogin::SESSION_KEY));
        $this->assertSame($user, $context->user());


        $login->logout();
        $this->assertNull($context->user());
        $this->assertFalse($session->has(SessionLogin::SESSION_KEY));
    }

    public function testFailedLoginsAreRateLimited(): void
    {
        [$login] = $this->login();
        foreach (range(1, 5) as $attempt) {
            $this->assertNull($login->attempt('ada@example.com', 'wrong', '198.51.100.1'));
        }

        $this->expectException(TooManyRequestsHttpException::class);
        $login->attempt('ada@example.com', 'secret-pass', '198.51.100.1');
    }

    public function testAPasswordChangeSignsOutOtherSessions(): void
    {
        $hasher = new PasswordHasher(['cost' => 4], PASSWORD_BCRYPT);
        $users = new LoginUsers($hasher->hash('secret-pass'));
        $stolen = new Session();
        (new SessionLogin($users, $hasher, $stolen, new SecurityContext()))->attempt('ada@example.com', 'secret-pass');
        $this->assertSame('1', $this->sessionUser($users, $stolen->all()), 'signed in before the change');

        $users->hash = $hasher->hash('a new password');

        $this->assertNull($this->sessionUser($users, $stolen->all()), 'signed out after it');
        $this->assertNull($this->sessionUser($users, [SessionLogin::SESSION_KEY => '1']), 'and so is a session that remembers no password');
    }

    public function testOwnSignInsDoNotResetTheAddressLimit(): void
    {
        $hasher = new PasswordHasher(['cost' => 4], PASSWORD_BCRYPT);
        $users = new LoginUsers($hasher->hash('secret-pass'));
        $login = new SessionLogin($users, $hasher, new Session(), new SecurityContext(), new RateLimiter(new ArrayCache(), static fn (): int => 1_800_000_000));

        $guesses = 0;
        try {
            foreach (range(1, 40) as $i) {
                if ($i % 4 === 0) {
                    $login->attempt('ada@example.com', 'secret-pass', '203.0.113.9');   // the attacker's own account
                }
                $login->attempt("victim{$i}@example.com", 'guess', '203.0.113.9');
                $guesses++;
            }
        } catch (TooManyRequestsHttpException) {
        }

        $this->assertSame(5, $guesses);
    }

    public function testWithoutAnAddressNobodyIsLockedOutByOthers(): void
    {
        $hasher = new PasswordHasher(['cost' => 4], PASSWORD_BCRYPT);
        $login = new SessionLogin(new LoginUsers($hasher->hash('secret-pass')), $hasher, new Session(), new SecurityContext(), new RateLimiter(new ArrayCache(), static fn (): int => 1_800_000_000));

        foreach (range(1, 8) as $i) {
            $this->assertNull($login->attempt("nobody{$i}@example.com", 'x'));
        }

        $this->assertNotNull($login->attempt('ada@example.com', 'secret-pass'), 'the per-login limit still applies, but not a shared one');
    }

    /**
     * 2.28: before, five wrong passwords from anywhere locked the owner out for the window too.
     */
    public function testAnAttackerLocksOutOnlyThemselvesNotTheOwner(): void
    {
        [$login] = $this->lockoutLogin();
        foreach (range(1, 5) as $_) {
            $this->assertNull($login->attempt('ada@example.com', 'guess', '203.0.113.9'));
        }
        try {
            $login->attempt('ada@example.com', 'guess', '203.0.113.9');
            $this->fail('The attacker\'s sixth try was let through.');
        } catch (TooManyRequestsHttpException) {
        }

        $this->assertNotNull($login->attempt('ada@example.com', 'secret-pass', '198.51.100.1'), 'Ada, from her own address, signs in');
    }

    public function testTheOwnersSignInStartsTheirAddressAgain(): void
    {
        [$login] = $this->lockoutLogin();
        foreach (range(1, 4) as $_) {
            $login->attempt('ada@example.com', 'mistyped', '198.51.100.1');
        }
        $this->assertNotNull($login->attempt('ada@example.com', 'secret-pass', '198.51.100.1'));

        // Her sixth try of this login from this address: it would be refused had her sign-in not started the count
        // again (the limit per address, five failures from it, still holds, as since 2.19.1).
        $this->assertNull($login->attempt('ada@example.com', 'mistyped again', '198.51.100.1'));
    }

    public function testManyAddressesTogetherAreHeldByTheLimitPerLogin(): void
    {
        [$login] = $this->lockoutLogin(perLogin: 12);
        $tries = 0;
        try {
            foreach (range(1, 40) as $i) {
                // A botnet: each address stays under its own limit of five.
                $login->attempt('ada@example.com', 'guess', "203.0.113.{$i}");
                $login->attempt('ada@example.com', 'guess', "203.0.113.{$i}");
                $tries += 2;
            }
        } catch (TooManyRequestsHttpException) {
        }
        $this->assertSame(12, $tries, 'the login takes twelve tries from all addresses together');

        $this->expectException(TooManyRequestsHttpException::class);
        $login->attempt('ada@example.com', 'secret-pass', '198.51.100.1');   // and then Ada too, without a known device
    }

    public function testTheLimitPerLoginIsTenTimesThePerAddressLimitByDefault(): void
    {
        [$login] = $this->lockoutLogin();
        $tries = 0;
        try {
            foreach (range(1, 100) as $i) {
                $login->attempt('ada@example.com', 'guess', "203.0.113.{$i}");
                $tries++;
            }
        } catch (TooManyRequestsHttpException) {
        }

        $this->assertSame(50, $tries);
    }

    public function testAKnownDeviceSignsInWhileTheLoginIsLockedOut(): void
    {
        [$login] = $this->lockoutLogin(perLogin: 3);
        $first = $login->start('ada@example.com', 'secret-pass', '198.51.100.1');
        $this->assertTrue($first->signedIn());
        $device = $first->knownDevice;
        $this->assertIsString($device, 'each sign-in gives a known-device token');

        foreach (range(1, 3) as $i) {
            $login->attempt('ada@example.com', 'guess', "203.0.113.{$i}");
        }
        try {
            $login->start('ada@example.com', 'secret-pass', '198.51.100.1');
            $this->fail('Locked out without the cookie.');
        } catch (TooManyRequestsHttpException) {
        }

        $this->assertTrue($login->start('ada@example.com', 'secret-pass', '198.51.100.1', knownDevice: $device)->signedIn(), 'with it, Ada gets in');
        $this->assertFalse($login->start('ada@example.com', 'wrong', '198.51.100.1', knownDevice: $device)->signedIn(), 'it never replaces the password');
    }

    public function testAKnownDeviceOfAnotherUserOrAnotherTokenDoesNotPass(): void
    {
        $hasher = new PasswordHasher(['cost' => 4], PASSWORD_BCRYPT);
        $signer = $this->signer();
        $users = new TwoLoginUsers($hasher->hash('secret-pass'));
        $login = new SessionLogin($users, $hasher, new Session(), new SecurityContext(), new RateLimiter(new ArrayCache(), fn (): int => $this->now), maxAttemptsPerLogin: 2, knownDevices: $signer);

        $graces = $login->start('grace@example.com', 'secret-pass', '198.51.100.2')->knownDevice;
        $this->assertIsString($graces);
        $login->attempt('ada@example.com', 'guess', '203.0.113.1');
        $login->attempt('ada@example.com', 'guess', '203.0.113.2');

        foreach ([
            'Grace\'s device' => $graces,
            'a CSRF token' => (new CsrfTokens($signer))->issue(),
            'a bearer token for Ada' => $signer->issue('1', 600),
            'signed with another key' => (new TokenSigner(str_repeat('o', 32), fn (): int => $this->now))->issue('known-device:' . hash('sha256', 'zana.known-device|1'), 600),
            'garbage' => 'garbage',
        ] as $name => $token) {
            try {
                $login->start('ada@example.com', 'secret-pass', '198.51.100.1', knownDevice: $token);
                $this->fail("Let through with {$name}.");
            } catch (TooManyRequestsHttpException) {
                $this->addToAssertionCount(1);
            }
        }
    }

    public function testAKnownDeviceExpiresAndSaysNothingAboutTheUser(): void
    {
        [$login] = $this->lockoutLogin(perLogin: 1);
        $device = $login->start('ada@example.com', 'secret-pass', '198.51.100.1')->knownDevice;
        $this->assertIsString($device);
        $this->assertStringNotContainsString('ada', strtolower((string) base64_decode(strtr(explode('.', $device)[0], '-_', '+/'))));
        $this->assertMatchesRegularExpression('/^known-device:[0-9a-f]{64}$/', $this->signer()->verify($device)->subject, 'a hash, never the identifier');

        $login->attempt('ada@example.com', 'guess', '203.0.113.1');
        $this->now += SessionLogin::KNOWN_DEVICE_LIFETIME + 1;
        // The window has passed too, so lock the login again first.
        $login->attempt('ada@example.com', 'guess', '203.0.113.1');

        $this->expectException(TooManyRequestsHttpException::class);
        $login->start('ada@example.com', 'secret-pass', '198.51.100.1', knownDevice: $device);
    }

    public function testTheProviderWiresTheLimitAndTheKnownDevice(): void
    {
        $app = Application::configure(sys_get_temp_dir())
            ->withProviders(SecurityServiceProvider::class, SessionServiceProvider::class, CacheServiceProvider::class)
            ->withConfiguration(['security.secret' => str_repeat('s', 40), 'security.login.max_attempts_per_login' => 7, 'security.login.known_device_days' => 1, 'cache.default' => 'array'])
            ->withServices(static function (ServiceCollectionInterface $services): void {
                $services->singleton(PasswordUserProviderInterface::class, static fn (): LoginUsers => new LoginUsers((new PasswordHasher(['cost' => 4], PASSWORD_BCRYPT))->hash('secret-pass')));
            })
            ->build();
        $scope = $app->container()->createScope();
        $scope->get(SessionContext::class)->set(new Session());
        $login = $scope->get(SessionLogin::class);
        $this->assertInstanceOf(SessionLogin::class, $login);

        $device = $login->start('ada@example.com', 'secret-pass', '198.51.100.1')->knownDevice;
        $this->assertIsString($device);
        $claims = $app->container()->get(TokenSigner::class)->verify($device);
        $this->assertSame(86_400, $claims->expiresAt->getTimestamp() - $claims->issuedAt->getTimestamp(), 'known_device_days');

        $tries = 0;
        try {
            foreach (range(1, 20) as $i) {
                $login->attempt('ada@example.com', 'guess', "203.0.113.{$i}");
                $tries++;
            }
        } catch (TooManyRequestsHttpException) {
        }
        $this->assertSame(7, $tries, 'max_attempts_per_login');
    }

    // ── 2.31: the known-device cookie, by middleware ───────────────────────

    public function testTheMiddlewareSetsTheCookieAndTheOwnerGetsInWhileLockedOut(): void
    {
        $device = new KnownDevice();
        $hasher = new PasswordHasher(['cost' => 4], PASSWORD_BCRYPT);
        $login = new SessionLogin(new LoginUsers($hasher->hash('secret-pass')), $hasher, new Session(), new SecurityContext(), new RateLimiter(new ArrayCache(), fn (): int => $this->now), maxAttemptsPerLogin: 3, knownDevices: $this->signer(), device: $device);
        $middleware = new KnownDeviceMiddleware($device, lifetime: 600);
        // The application's own controller: it calls attempt() as before 2.28, and knows nothing of the cookie.
        $controller = new SignsIn($login);

        $signedIn = $middleware->process(new ServerRequest('POST', 'https://example.com/login'), $controller->as('ada@example.com', 'secret-pass', '198.51.100.1'));
        $cookie = $signedIn->getHeaderLine('Set-Cookie');
        $this->assertMatchesRegularExpression('/^zana_device=[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-.]+; Path=\/; Max-Age=600; HttpOnly; SameSite=Lax; Secure$/', $cookie);
        $token = substr((string) strstr($cookie, ';', true), strlen('zana_device='));

        foreach (range(1, 3) as $i) {   // Mallory, from three addresses
            $middleware->process(new ServerRequest('POST', '/login'), $controller->as('ada@example.com', 'guess', "203.0.113.{$i}"));
        }
        try {
            $middleware->process(new ServerRequest('POST', '/login'), $controller->as('ada@example.com', 'secret-pass', '198.51.100.1'));
            $this->fail('Locked out without the cookie.');
        } catch (TooManyRequestsHttpException) {
        }

        $again = $middleware->process((new ServerRequest('POST', '/login'))->withCookieParams(['zana_device' => $token]), $controller->as('ada@example.com', 'secret-pass', '198.51.100.1'));
        $this->assertSame(200, $again->getStatusCode(), 'Ada, with her cookie, gets in');
        $this->assertStringNotContainsString('Secure', $again->getHeaderLine('Set-Cookie'), 'plain HTTP: no Secure');
    }

    public function testAFailedSignInSetsNoCookieAndHostileCookiesAreNotRead(): void
    {
        $device = new KnownDevice();
        $hasher = new PasswordHasher(['cost' => 4], PASSWORD_BCRYPT);
        $login = new SessionLogin(new LoginUsers($hasher->hash('secret-pass')), $hasher, new Session(), new SecurityContext(), new RateLimiter(new ArrayCache(), fn (): int => $this->now), maxAttemptsPerLogin: 1, knownDevices: $this->signer(), device: $device);
        $middleware = new KnownDeviceMiddleware($device, cookie: 'device');
        $controller = new SignsIn($login);

        $failed = $middleware->process(new ServerRequest('POST', '/login'), $controller->as('ada@example.com', 'wrong', '203.0.113.1'));
        $this->assertSame('', $failed->getHeaderLine('Set-Cookie'), 'no sign-in, no cookie');

        foreach ([['device' => ['an', 'array']], ['device' => str_repeat('a', 600) . '.' . str_repeat('b', 600)], ['device' => "x.y\r\nSet-Cookie: evil=1"], ['device' => '']] as $cookies) {
            $middleware->process((new ServerRequest('POST', '/login'))->withCookieParams($cookies), new PassThrough());
            $this->assertNull($device->presented(), 'not given to SessionLogin: ' . json_encode($cookies));
        }
        $this->expectException(TooManyRequestsHttpException::class);   // and so the lock holds
        $middleware->process((new ServerRequest('POST', '/login'))->withCookieParams(['device' => 'not.a-token']), $controller->as('ada@example.com', 'secret-pass', '198.51.100.1'));
    }

    public function testTheCookieFollowsTheBasePath(): void
    {
        $device = new KnownDevice();
        $device->issue('a.b');
        $response = (new KnownDeviceMiddleware($device))->process((new ServerRequest('POST', '/shop/login'))->withAttribute(\Zana\Http\BasePath::ATTRIBUTE, '/shop'), new PassThrough());

        $this->assertStringContainsString('; Path=/shop;', $response->getHeaderLine('Set-Cookie'));
    }

    public function testTheProviderWiresTheCookieMiddleware(): void
    {
        $app = Application::configure(sys_get_temp_dir())
            ->withProviders(SecurityServiceProvider::class, SessionServiceProvider::class, CacheServiceProvider::class)
            ->withConfiguration(['security.secret' => str_repeat('s', 40), 'security.login.known_device_cookie' => 'mine', 'cache.default' => 'array'])
            ->withServices(static function (ServiceCollectionInterface $services): void {
                $services->singleton(PasswordUserProviderInterface::class, static fn (): LoginUsers => new LoginUsers((new PasswordHasher(['cost' => 4], PASSWORD_BCRYPT))->hash('secret-pass')));
            })
            ->build();
        $scope = $app->container()->createScope();
        $scope->get(SessionContext::class)->set(new Session());
        $login = $scope->get(SessionLogin::class);
        $middleware = $scope->get(KnownDeviceMiddleware::class);
        $this->assertInstanceOf(SessionLogin::class, $login);
        $this->assertInstanceOf(KnownDeviceMiddleware::class, $middleware);

        $response = $middleware->process(new ServerRequest('POST', '/login'), (new SignsIn($login))->as('ada@example.com', 'secret-pass', '198.51.100.1'));
        $this->assertStringStartsWith('mine=', $response->getHeaderLine('Set-Cookie'), 'the same KnownDevice in the scope');
        $this->assertStringContainsString('Max-Age=7776000', $response->getHeaderLine('Set-Cookie'));
    }

    /**
     * @return array{SessionLogin}
     */
    private function lockoutLogin(?int $perLogin = null): array
    {
        $hasher = new PasswordHasher(['cost' => 4], PASSWORD_BCRYPT);

        return [new SessionLogin(new LoginUsers($hasher->hash('secret-pass')), $hasher, new Session(), new SecurityContext(), new RateLimiter(new ArrayCache(), fn (): int => $this->now), maxAttemptsPerLogin: $perLogin, knownDevices: $this->signer())];
    }

    /**
     * @param array<string, mixed> $data
     */
    private function sessionUser(LoginUsers $users, array $data): ?string
    {
        $sessions = new SessionContext();
        $sessions->set(new Session(str_repeat('b', 64), $data));
        $context = new SecurityContext();
        (new SessionAuthenticationMiddleware($sessions, $users, $context))->process(new ServerRequest('GET', '/admin'), new PassThrough());

        return $context->user()?->identifier();
    }

    public function testOldHashesAreUpgradedAtLogin(): void
    {
        $users = new LoginUsers((new PasswordHasher(['cost' => 4], PASSWORD_BCRYPT))->hash('secret-pass'));
        $login = new SessionLogin($users, new PasswordHasher(['memory_cost' => 8192, 'time_cost' => 1]), new Session(), new SecurityContext());

        $login->attempt('ada@example.com', 'secret-pass');

        $this->assertStringStartsWith('$argon2id$', $users->hash);
    }

    public function testTheSessionUserIsAuthenticatedAndAnonymousBrowsersAreSentToTheLoginPage(): void
    {
        $users = new LoginUsers((new PasswordHasher(['cost' => 4], PASSWORD_BCRYPT))->hash('secret-pass'));
        $sessions = new SessionContext();
        $sessions->set(new Session(str_repeat('a', 64), [SessionLogin::SESSION_KEY => '1', SessionLogin::PASSWORD_KEY => SessionLogin::passwordFingerprint($users->hash)]));
        $context = new SecurityContext();

        $middleware = new SessionAuthenticationMiddleware($sessions, $users, $context, '/login');
        $middleware->process(new ServerRequest('GET', '/admin'), new PassThrough());
        $this->assertSame('1', $context->user()?->identifier());

        $anonymous = new SessionContext();
        $anonymous->set(new Session());
        $guarded = new class () implements RequestHandlerInterface {
            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                throw new UnauthorizedHttpException();
            }
        };
        $middleware = new SessionAuthenticationMiddleware($anonymous, $users, new SecurityContext(), '/login');

        $redirect = $middleware->process(new ServerRequest('GET', '/admin/posts?page=2', ['Accept' => 'text/html']), $guarded);
        $this->assertSame([303, '/login?to=%2Fadmin%2Fposts%3Fpage%3D2'], [$redirect->getStatusCode(), $redirect->getHeaderLine('Location')]);

        $this->expectException(UnauthorizedHttpException::class);
        $middleware->process(new ServerRequest('GET', '/admin/posts', ['Accept' => 'application/json']), $guarded);
    }

    public function testPasswordResetLinksWorkOnceAndDieWithThePassword(): void
    {
        $users = new LoginUsers('hash-1');
        $resets = new PasswordResetTokens($this->signer(), new ArrayCache(), $users);
        $user = $users->findByIdentifier('1');
        assert($user !== null);

        $token = $resets->issue($user);
        $this->assertSame('1', $resets->check($token)?->identifier());
        $this->assertSame('1', $resets->consume($token)?->identifier());
        $this->assertNull($resets->consume($token), 'used up');

        $second = $resets->issue($user);
        $users->hash = 'hash-2';   // the password changed
        $this->assertNull($resets->check($second));
        $this->assertNull($resets->check('garbage'));
    }

    /**
     * @return array{SessionLogin, Session, SecurityContext}
     */
    private function login(): array
    {
        $hasher = new PasswordHasher(['cost' => 4], PASSWORD_BCRYPT);
        $session = new Session();
        $context = new SecurityContext();

        return [new SessionLogin(new LoginUsers($hasher->hash('secret-pass')), $hasher, $session, $context, $this->limiter()), $session, $context];
    }

    private function limiter(): RateLimiter
    {
        static $cache = null;
        $cache ??= new ArrayCache();

        return new RateLimiter($cache, fn (): int => $this->now);
    }

    private function signer(): TokenSigner
    {
        return new TokenSigner(str_repeat('k', 32), fn (): int => $this->now);
    }
}

final class LimitedController
{
    #[RateLimit(max: 2, per: 60, strategy: 'fixed')]
    public function send(): string
    {
        return 'sent';
    }

    public function free(): string
    {
        return 'free';
    }
}

/** An application's sign-in controller, as MMC's is: attempt(), and nothing about cookies. */
final readonly class SignsIn
{
    public function __construct(private SessionLogin $login)
    {
    }

    public function as(string $email, string $password, string $ip): RequestHandlerInterface
    {
        $login = $this->login;

        return new class ($login, $email, $password, $ip) implements RequestHandlerInterface {
            public function __construct(private SessionLogin $login, private string $email, private string $password, private string $ip)
            {
            }

            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                return new Response($this->login->attempt($this->email, $this->password, $this->ip) === null ? 422 : 200);
            }
        };
    }
}

final readonly class PassThrough implements RequestHandlerInterface
{
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        return new Response();
    }
}

/** Ada (1) and Grace (2), with one password. */
final readonly class TwoLoginUsers implements PasswordUserProviderInterface
{
    public function __construct(private string $hash)
    {
    }

    public function findByIdentifier(string $identifier): ?UserInterface
    {
        return in_array($identifier, ['1', '2'], true) ? new NumberedUser($identifier) : null;
    }

    public function findByLogin(string $login): ?UserInterface
    {
        return match (strtolower(trim($login))) {
            'ada@example.com' => new NumberedUser('1'),
            'grace@example.com' => new NumberedUser('2'),
            default => null,
        };
    }

    public function passwordHashFor(UserInterface $user): string
    {
        return $this->hash;
    }
}

final readonly class NumberedUser implements UserInterface
{
    public function __construct(private string $id)
    {
    }

    public function identifier(): string
    {
        return $this->id;
    }

    public function roles(): array
    {
        return [];
    }
}

final class BackOfficeUser implements UserInterface
{
    public function identifier(): string
    {
        return '1';
    }

    public function roles(): array
    {
        return ['editor'];
    }
}

final class LoginUsers implements PasswordUserProviderInterface, PasswordUpgraderInterface
{
    private BackOfficeUser $editor;

    public function __construct(public string $hash)
    {
        $this->editor = new BackOfficeUser();
    }

    public function findByIdentifier(string $identifier): ?UserInterface
    {
        return $identifier === '1' ? $this->editor : null;
    }

    public function findByLogin(string $login): ?UserInterface
    {
        return strtolower(trim($login)) === 'ada@example.com' ? $this->editor : null;
    }

    public function passwordHashFor(UserInterface $user): string
    {
        return $this->hash;
    }

    public function upgradePassword(UserInterface $user, string $newHash): void
    {
        $this->hash = $newHash;
    }
}
