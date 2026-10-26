<?php

declare(strict_types=1);

namespace Zana\Security\Tests;

use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;
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
        $sessions->set(new Session(str_repeat('a', 64), [SessionLogin::SESSION_KEY => '1']));
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

final readonly class PassThrough implements RequestHandlerInterface
{
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        return new Response();
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
