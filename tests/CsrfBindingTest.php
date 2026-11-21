<?php

declare(strict_types=1);

namespace Zana\Security\Tests;

use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Zana\Core\Application;
use Zana\Http\Exception\ForbiddenHttpException;
use Zana\Security\CsrfBinding;
use Zana\Security\CsrfTokens;
use Zana\Security\Middleware\CsrfMiddleware;
use Zana\Security\SecurityServiceProvider;
use Zana\Security\TokenSigner;
use Zana\Session\Session;

/**
 * 2.28, security.csrf.bind_to_session: one visitor's token no longer passes for another's, when they have a session.
 * Each visitor here is a Session, as SessionMiddleware would load it for their requests.
 */
final class CsrfBindingTest extends TestCase
{
    private const string SECRET = 'a-test-secret-that-is-long-enough-1234';

    public function testOffByDefaultAnyVisitorsTokenPassesAsBefore(): void
    {
        [$tokens, $middleware] = $this->csrf(bind: false);
        $mallory = new Session('mallory', []);
        $alice = new Session('alice', []);

        $token = $this->page($middleware, $mallory, $tokens);

        $this->assertSame(204, $this->post($middleware, $alice, $token)->getStatusCode(), 'stateless, as before 2.28');
        $this->assertNull($mallory->get(CsrfBinding::SEED_KEY), 'nothing written to the session');
    }

    public function testAnotherVisitorsTokenIsRefused(): void
    {
        [$tokens, $middleware] = $this->csrf();
        $mallory = new Session('mallory', []);
        $alice = new Session('alice', []);

        // Mallory gets a valid token from the site, and makes Alice's browser post it.
        $token = $this->page($middleware, $mallory, $tokens);
        $this->assertRefused(fn () => $this->post($middleware, $alice, $token), 'Alice has a session, and the token is not hers');

        // Alice's own token passes, and goes on passing in her session.
        $own = $this->page($middleware, $alice, $tokens);
        $statuses = [];
        foreach ([1, 2] as $_) {
            $statuses[] = $this->post($middleware, $alice, $own)->getStatusCode();
        }
        $this->assertSame([204, 204], $statuses);
        $this->assertRefused(fn () => $this->post($middleware, $mallory, $own), 'nor hers Mallory\'s');
    }

    public function testADisabledBindingTiesNothingEvenGivenASession(): void
    {
        $binding = new CsrfBinding(false);
        $alice = new Session('alice', []);

        $this->assertNull($binding->during($alice, static fn (): ?string => $binding->forIssue()));
        $this->assertSame([], $alice->all());
    }

    public function testAMalformedSeedInTheSessionIsReplaced(): void
    {
        [$tokens, $middleware] = $this->csrf();
        $alice = new Session('alice', [CsrfBinding::SEED_KEY => 'short']);

        $this->page($middleware, $alice, $tokens);
        $seed = $alice->get(CsrfBinding::SEED_KEY);
        $this->assertIsString($seed);
        $this->assertSame(64, strlen($seed), 'a seed someone could guess is never used');
    }

    public function testATokenWithoutBindingIsRefusedOnceTheVisitorHasASession(): void
    {
        [$tokens, $middleware] = $this->csrf();
        $alice = new Session('alice', []);

        // Printed outside CsrfMiddleware, or before Alice had a session: no binding.
        $unbound = $tokens->issue();
        $this->assertRefused(fn () => $this->post($middleware, $alice, $unbound), 'Alice has never seen a form, and still a stateless token does not pass');
        $this->assertIsString($alice->get(CsrfBinding::SEED_KEY), 'her session got its seed');
    }

    public function testAVisitorWithoutASessionKeepsStatelessTokensAndNoSessionIsStarted(): void
    {
        [$tokens, $middleware] = $this->csrf();
        $anonymous = new Session(null, []);

        $token = $this->page($middleware, $anonymous, $tokens);

        $this->assertSame([], $anonymous->all(), 'no seed, so nothing to save and no cookie');
        $this->assertSame(204, $this->post($middleware, new Session(null, []), $token)->getStatusCode(), 'a cached public form still works');
        $this->assertSame(204, $this->post($middleware, null, $token)->getStatusCode(), 'and without SessionMiddleware');
    }

    public function testASignInKeepsTheBindingWhileTheIdChanges(): void
    {
        [$tokens, $middleware] = $this->csrf();
        $alice = new Session('alice', []);
        $token = $this->page($middleware, $alice, $tokens);

        $alice->regenerate();   // as SessionLogin does: the id is null until the session is saved, the data kept
        $this->assertNull($alice->id());
        $this->assertSame(204, $this->post($middleware, $alice, $token)->getStatusCode());
        $this->assertNotSame('', $this->page($middleware, $alice, $tokens));
    }

    public function testASignOutEndsTheTokensOfTheSession(): void
    {
        [$tokens, $middleware] = $this->csrf();
        $alice = new Session('alice', []);
        $token = $this->page($middleware, $alice, $tokens);

        $alice->invalidate();
        $next = new Session('alice-again', []);   // her next session, after signing in again
        $this->assertRefused(fn () => $this->post($middleware, $next, $token), 'a token of the old session');
    }

    public function testTheTokenCarriesAHashOfTheSeedNeverTheSeed(): void
    {
        [$tokens, $middleware] = $this->csrf();
        $alice = new Session('alice', []);
        $token = $this->page($middleware, $alice, $tokens);
        $seed = $alice->get(CsrfBinding::SEED_KEY);
        $this->assertIsString($seed);

        $claims = (new TokenSigner(self::SECRET))->verify($token);
        $this->assertIsString($claims->claim('bind'));
        $this->assertStringNotContainsString($seed, $token);
        $this->assertStringNotContainsString($seed, base64_decode(strtr(explode('.', $token)[0], '-_', '+/'), false) ?: '');
    }

    public function testAForgedOrMissingBindingIsRefused(): void
    {
        [$tokens, $middleware] = $this->csrf();
        $alice = new Session('alice', []);
        $this->page($middleware, $alice, $tokens);
        $signer = new TokenSigner(self::SECRET);

        foreach (['', 'x', str_repeat('0', 32), 7] as $bind) {
            // Only someone with the secret can sign these: they show the claim itself is checked.
            $forged = $signer->issue('csrf:default', 600, ['nonce' => bin2hex(random_bytes(16)), 'bind' => $bind]);
            $this->assertRefused(fn () => $this->post($middleware, $alice, $forged), 'bind: ' . var_export($bind, true));
        }
    }

    public function testTheSessionIsPutBackAfterTheRequestAlsoWhenItFails(): void
    {
        [$tokens, $middleware] = $this->csrf();
        $alice = new Session('alice', []);
        $this->assertRefused(fn () => $this->post($middleware, $alice, 'garbage'), 'refused');

        // The next request, in a long-running worker, is not tied to Alice's session.
        $this->assertSame([], (new Session(null, []))->all());
        $this->assertNull($this->binding?->forIssue(), 'outside a request, no session');
        $this->assertArrayNotHasKey('bind', (array) (new TokenSigner(self::SECRET))->verify($tokens->issue())->claims);
    }

    public function testTheProviderTurnsItOnFromConfiguration(): void
    {
        foreach ([false, true] as $on) {
            $container = Application::configure(sys_get_temp_dir())
                ->withProviders(SecurityServiceProvider::class)
                ->withConfiguration(['security.secret' => self::SECRET, 'security.csrf.bind_to_session' => $on])
                ->build()->container();
            $binding = $container->get(CsrfBinding::class);
            $this->assertInstanceOf(CsrfBinding::class, $binding);
            $this->assertSame($on, $binding->enabled());
        }
    }

    private ?CsrfBinding $binding = null;

    /**
     * @return array{0: CsrfTokens, 1: \Closure(?Session): CsrfMiddleware}
     */
    private function csrf(bool $bind = true): array
    {
        $this->binding = new CsrfBinding($bind);
        $tokens = new CsrfTokens(new TokenSigner(self::SECRET), binding: $this->binding);
        $binding = $this->binding;

        return [$tokens, static fn (?Session $session): CsrfMiddleware => new CsrfMiddleware($tokens, null, $binding, static fn (): ?Session => $session)];
    }

    /**
     * A GET of a page that prints a form, as the visitor: the token it printed.
     *
     * @param \Closure(?Session): CsrfMiddleware $middleware
     */
    private function page(\Closure $middleware, ?Session $visitor, CsrfTokens $tokens): string
    {
        $response = $middleware($visitor)->process(new ServerRequest('GET', '/form'), new class ($tokens) implements RequestHandlerInterface {
            public function __construct(private CsrfTokens $tokens)
            {
            }

            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                return new Response(200, [], $this->tokens->issue());   // the page, printing its form's token
            }
        });

        return (string) $response->getBody();
    }

    /**
     * @param \Closure(?Session): CsrfMiddleware $middleware
     */
    private function post(\Closure $middleware, ?Session $visitor, string $token): ResponseInterface
    {
        $request = (new ServerRequest('POST', '/form'))->withParsedBody([CsrfTokens::FIELD => $token]);

        return $middleware($visitor)->process($request, new class implements RequestHandlerInterface {
            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                return new Response(204);
            }
        });
    }

    private function assertRefused(\Closure $request, string $message): void
    {
        try {
            $request();
            $this->fail("Accepted: {$message}");
        } catch (ForbiddenHttpException) {
            $this->addToAssertionCount(1);
        }
    }
}
