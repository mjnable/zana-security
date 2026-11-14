<?php

declare(strict_types=1);

namespace Zana\Security\Tests;

use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use Zana\Container\Contracts\ServiceCollectionInterface;
use Zana\Core\Application;
use Zana\Core\ApplicationInterface;
use Zana\Core\Inspection\ApplicationCheck;
use Zana\Core\Inspection\Finding;
use Zana\Core\Inspection\Severity;
use Zana\Http\Exception\ForbiddenHttpException;
use Zana\Http\HttpServiceProvider;
use Zana\Routing\Attribute\PublicRoute;
use Zana\Routing\Router;
use Zana\Routing\RoutingServiceProvider;
use Zana\Security\Attribute\VerifyHuman;
use Zana\Security\Bot\BotVerdict;
use Zana\Security\Bot\BotVerifierInterface;
use Zana\Security\Bot\FakeBotVerifier;
use Zana\Security\Bot\NullBotVerifier;
use Zana\Security\Event\BotVerificationFailed;
use Zana\Security\Inspection\BotVerificationCheck;
use Zana\Security\Middleware\BotVerificationMiddleware;
use Zana\Security\SecurityException;
use Zana\Security\SecurityServiceProvider;

/**
 * 2.25, FE-64: #[VerifyHuman] and BotVerificationMiddleware ask a bot
 * verifier (a CAPTCHA provider) about the request's token before the
 * handler runs; security holds no provider code.
 */
final class BotVerificationTest extends TestCase
{
    // ── The middleware ─────────────────────────────────────────────────────

    public function testAPersonsTokenGoesThroughWithTheClientAndTheAction(): void
    {
        $bots = new FakeBotVerifier(['person' => true]);
        $handler = new Answer();

        $response = (new BotVerificationMiddleware($bots))->process(self::post(['bot_token' => 'person']), $handler);

        $this->assertSame([200, 1], [$response->getStatusCode(), $handler->calls]);
        $this->assertSame([['token' => 'person', 'clientIp' => '198.51.100.7', 'action' => 'checkout']], $bots->calls);
    }

    public function testTheTokenMayComeInAHeaderForAnApi(): void
    {
        $response = (new BotVerificationMiddleware(new FakeBotVerifier(['person' => true])))->process(self::post([])->withHeader('X-Bot-Token', 'person'), new Answer());

        $this->assertSame(200, $response->getStatusCode());
    }

    /**
     * @return iterable<string, array{0: BotVerdict|bool, 1: list<string>}>
     */
    public static function refusals(): iterable
    {
        yield 'the provider says bot' => [BotVerdict::bot(['invalid-input-response']), ['invalid-input-response']];
        yield 'bot, no code' => [false, ['invalid-input-response']];
        yield 'a reused token' => [BotVerdict::bot(['timeout-or-duplicate']), ['timeout-or-duplicate']];
        yield 'a low score' => [BotVerdict::human(0.3, 'checkout'), ['low-score']];
        yield 'another action' => [BotVerdict::human(0.9, 'login'), ['action-mismatch']];
        yield 'another site' => [BotVerdict::human(0.9, 'checkout', 'evil.example'), ['hostname-mismatch']];
        yield 'unreachable' => [BotVerdict::unavailable('timeout'), ['unavailable', 'timeout']];
        yield 'a hostile code' => [BotVerdict::bot(['<script>alert(1)</script>', 'ok-code']), ['unreadable-code', 'ok-code']];
    }

    /**
     * @param list<string> $reasons
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('refusals')]
    public function testRefusedBeforeTheHandler(BotVerdict|bool $verdict, array $reasons): void
    {
        $events = new RecordingDispatcher();
        $handler = new Answer();
        $middleware = new BotVerificationMiddleware(new FakeBotVerifier(['t0k3n-secret' => $verdict]), ['www.example.com'], events: $events);

        try {
            $middleware->process(self::post(['bot_token' => 't0k3n-secret']), $handler);
            self::fail('A bot got through.');
        } catch (ForbiddenHttpException $e) {
            $this->assertSame('Please confirm that you are a person, then send the form again.', $e->getMessage());
        }
        $this->assertSame(0, $handler->calls);
        $event = $events->events[0];
        $this->assertInstanceOf(BotVerificationFailed::class, $event);
        $this->assertSame(['/checkout', 'checkout', $reasons, '198.51.100.7'], [$event->path, $event->action, $event->reasons, $event->clientIp]);
        $this->assertSame('security.bot_verification_failed', $event->action());
        $this->assertStringNotContainsString('t0k3n-secret', serialize($event), 'never the token');
    }

    public function testNoTokenOrAnOversizedOneIsNeverSentToTheProvider(): void
    {
        $bots = new FakeBotVerifier();
        $events = new RecordingDispatcher();
        $middleware = new BotVerificationMiddleware($bots, events: $events);

        foreach ([[], ['bot_token' => ''], ['bot_token' => ['a', 'b']], ['bot_token' => str_repeat('x', 4097)]] as $body) {
            try {
                $middleware->process(self::post($body), new Answer());
                self::fail('Refused without a token.');
            } catch (ForbiddenHttpException) {
            }
        }
        $this->assertSame([], $bots->calls);
        $this->assertSame([['missing-token'], ['missing-token'], ['missing-token'], ['oversized-token']], array_map(static fn (object $e): array => $e instanceof BotVerificationFailed ? $e->reasons : [], $events->events));
    }

    public function testTheScoreAtTheMinimumAndAnUnsaidActionOrSitePass(): void
    {
        $middleware = new BotVerificationMiddleware(new FakeBotVerifier(['a' => BotVerdict::human(0.5), 'b' => BotVerdict::human(0.9, 'checkout', 'WWW.Example.com')]), ['www.example.com']);

        $this->assertSame(200, $middleware->process(self::post(['bot_token' => 'a']), new Answer())->getStatusCode(), 'at the minimum, no action or site said');
        $this->assertSame(200, $middleware->process(self::post(['bot_token' => 'b']), new Answer())->getStatusCode(), 'the site in any case');
    }

    public function testAnUnreachableProviderCanBeAllowedAndIsLogged(): void
    {
        $logger = new SpamLog();
        $handler = new Answer();
        $middleware = new BotVerificationMiddleware(new FakeBotVerifier(['t' => BotVerdict::unavailable('timeout')]), onUnavailable: 'allow', logger: $logger);

        $this->assertSame(200, $middleware->process(self::post(['bot_token' => 't']), $handler)->getStatusCode());
        $this->assertSame(1, $handler->calls);
        $this->assertSame(['warning: The bot verifier could not be asked about a token.'], $logger->lines);
        $this->assertSame(['path' => '/checkout', 'reasons' => ['timeout']], $logger->contexts[0]);
    }

    public function testAVerifierThatThrowsIsUnavailableAndSaysWhy(): void
    {
        $events = new RecordingDispatcher();
        $logger = new SpamLog();
        $this->expectException(ForbiddenHttpException::class);
        try {
            (new BotVerificationMiddleware(new ThrowingVerifier(), events: $events, logger: $logger))->process(self::post(['bot_token' => 't']), new Answer());
        } finally {
            $event = $events->events[0];
            $this->assertInstanceOf(BotVerificationFailed::class, $event);
            $this->assertSame(['unavailable', \RuntimeException::class], $event->reasons);
            // Found on a real application, where a missing class looked like a provider that was down.
            $this->assertSame('error: The bot verifier failed; the request is refused.', $logger->lines[0]);
            $this->assertSame(['path' => '/checkout', 'exception' => \RuntimeException::class, 'message' => 'connection refused'], $logger->contexts[0]);
        }
    }

    public function testWithoutAVerifierItFailsClosed(): void
    {
        $this->expectException(SecurityException::class);
        $this->expectExceptionMessage('#[VerifyHuman] needs a bot verifier');
        (new BotVerificationMiddleware(null))->process(self::post(['bot_token' => 't']), new Answer());
    }

    public function testNotOnAGetNorWithoutTheAttribute(): void
    {
        $middleware = new BotVerificationMiddleware(null);

        $this->assertSame(200, $middleware->process(self::post([], 'GET'), new Answer())->getStatusCode());
        $this->assertSame(200, $middleware->process(self::post([])->withAttribute('_handler', [UnguardedForm::class, 'send']), new Answer())->getStatusCode());
        $this->assertSame(200, $middleware->process(self::post([])->withAttribute('_handler', null), new Answer())->getStatusCode());
    }

    public function testDeleteIsVerifiedToo(): void
    {
        $this->expectException(ForbiddenHttpException::class);
        (new BotVerificationMiddleware(new FakeBotVerifier()))->process(self::post([], 'DELETE'), new Answer());
    }

    public function testTheNullVerifierAcceptsEverything(): void
    {
        $this->assertTrue((new NullBotVerifier())->verify('anything')->human);
        $this->assertFalse((new NullBotVerifier())->scores());
    }

    // ── check ──────────────────────────────────────────────────────────────

    public function testCheckReportsVerificationThatVerifiesNothing(): void
    {
        $routes = static function (Router $r): void {
            $r->post('/checkout', [Checkout::class, 'pay']);                                                        // no middleware
            $r->post('/guarded', [Checkout::class, 'pay'])->middleware(BotVerificationMiddleware::class);           // fine
            $r->get('/checkout', [Checkout::class, 'pay'])->middleware(BotVerificationMiddleware::class);           // never verified
        };

        $this->assertSame([
            'Error Routes use #[VerifyHuman], but no bot verifier is registered, so every request to them is refused.',
            'Error POST /checkout has #[VerifyHuman], but BotVerificationMiddleware is not on the route, so no token is verified.',
            'Warning GET /checkout has #[VerifyHuman], but receives no POST, PUT, PATCH or DELETE, which is all that is verified.',
        ], self::lines($this->check($routes, strict: true)));

        $scored = $this->check(static fn (Router $r) => $r->post('/guarded', [Checkout::class, 'pay'])->middleware(BotVerificationMiddleware::class), verifier: new FakeBotVerifier(scores: false), strict: true);
        $this->assertSame(['Warning POST /guarded asks for a minimum score of 0.5, but ' . FakeBotVerifier::class . ' gives no score, so it is never applied.'], self::lines($scored));

        $good = static fn (Router $r) => $r->post('/guarded', [Checkout::class, 'pay'])->middleware(BotVerificationMiddleware::class);
        $this->assertSame([], $this->check($good, verifier: new FakeBotVerifier(scores: true), strict: true));
        $this->assertSame([], $this->check(static fn (Router $r) => $r->post('/open', [UnguardedForm::class, 'send']), strict: true), 'nothing to say without the attribute');
    }

    public function testAVerifierThatAsksNobodyIsAnErrorInProduction(): void
    {
        $routes = static fn (Router $r) => $r->post('/guarded', [Checkout::class, 'pay'])->middleware(BotVerificationMiddleware::class);

        $this->assertSame([], self::ids($this->check($routes, verifier: new NullBotVerifier(), environment: 'development', strict: true, all: false, ignoreScore: true)));
        $findings = $this->check($routes, verifier: new NullBotVerifier(), environment: 'production', strict: true, ignoreScore: true);
        $this->assertSame(Severity::Error, $findings[0]->severity);
        $this->assertStringContainsString(NullBotVerifier::class . ', which answers without asking a provider', $findings[0]->message);
        $this->assertStringContainsString('FakeBotVerifier', $this->check($routes, verifier: new FakeBotVerifier(scores: true), environment: 'production', strict: true)[0]->message);
    }

    public function testSettingsThatCannotBeUsed(): void
    {
        $this->assertSame(['security.bot.on_unavailable is "open", not "refuse" or "allow".'], self::messages($this->check(null, ['security.bot.on_unavailable' => 'open'], strict: true)));
        $this->assertSame(['security.bot.hostnames is not a list of host names, such as ["www.example.com"].'], self::messages($this->check(null, ['security.bot.hostnames' => 'www.example.com'], strict: true)));
        $this->assertSame(['security.bot.hostnames is not a list of host names, such as ["www.example.com"].'], self::messages($this->check(null, ['security.bot.hostnames' => ['https://www.example.com/']], strict: true)));
    }

    public function testTheMiddlewareInHttpMiddlewareIsReported(): void
    {
        $findings = $this->check(static fn (Router $r) => $r->post('/guarded', [Checkout::class, 'pay'])->middleware(BotVerificationMiddleware::class), ['http.middleware' => [BotVerificationMiddleware::class]], verifier: new FakeBotVerifier(scores: true), strict: true, all: true);

        $global = array_values(array_filter($findings, static fn (Finding $f): bool => $f->id === 'security.global_middleware'));
        $this->assertCount(1, $global);
        $this->assertStringContainsString('BotVerificationMiddleware is in http.middleware', $global[0]->message);
    }

    public function testTheApplicationWiresTheMiddleware(): void
    {
        $bots = new FakeBotVerifier(['t' => BotVerdict::human(0.9, 'checkout', 'evil.example')]);
        $app = $this->app(['security.bot.hostnames' => ['WWW.example.com']], $bots);

        $middleware = $app->container()->createScope()->get(BotVerificationMiddleware::class);
        $this->assertInstanceOf(BotVerificationMiddleware::class, $middleware);
        $this->expectException(ForbiddenHttpException::class);   // the hostnames, lower-cased, reach it
        $middleware->process(self::post(['bot_token' => 't']), new Answer());
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    /**
     * @param array<mixed> $body
     */
    private static function post(array $body, string $method = 'POST'): ServerRequestInterface
    {
        return (new ServerRequest($method, '/checkout', serverParams: ['REMOTE_ADDR' => '198.51.100.7']))
            ->withParsedBody($body)
            ->withAttribute('_handler', [Checkout::class, 'pay']);
    }

    /**
     * @param array<string, mixed> $config
     */
    private function app(array $config, ?BotVerifierInterface $verifier = null, string $environment = 'testing'): ApplicationInterface
    {
        return Application::configure(sys_get_temp_dir() . '/zana-security-bots')
            ->withEnvironment($environment)
            ->withConfiguration(['security.secret' => str_repeat('s', 40), 'app.debug' => false, ...$config])
            ->withProviders(HttpServiceProvider::class, RoutingServiceProvider::class, SecurityServiceProvider::class)
            ->withServices(static function (ServiceCollectionInterface $s) use ($verifier): void {
                if ($verifier !== null) {
                    $s->singleton(BotVerifierInterface::class, static fn (): BotVerifierInterface => $verifier);
                }
            })
            ->build();
    }

    /**
     * @param array<string, mixed> $config
     * @return list<Finding>
     */
    private function check(?\Closure $routes, array $config = [], ?BotVerifierInterface $verifier = null, string $environment = 'testing', bool $strict = false, bool $all = false, bool $ignoreScore = false): array
    {
        $app = $this->app(['security.strict' => $strict, ...$config], $verifier, $environment);
        if ($routes !== null) {
            $router = $app->container()->get(Router::class);
            assert($router instanceof Router);
            $routes($router);
        }
        $findings = [];
        foreach ($app->container()->tagged(ApplicationCheck::TAG) as $check) {
            if ($check instanceof BotVerificationCheck || ($all && $check instanceof ApplicationCheck)) {
                array_push($findings, ...$check->findings($app));
            }
        }

        return $ignoreScore ? array_values(array_filter($findings, static fn (Finding $f): bool => !str_contains($f->message, 'minimum score'))) : $findings;
    }

    /**
     * @param list<Finding> $findings
     * @return list<string>
     */
    private static function lines(array $findings): array
    {
        return array_map(static fn (Finding $f): string => "{$f->severity->name} {$f->message}", $findings);
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
     * @param list<Finding> $findings
     * @return list<string>
     */
    private static function ids(array $findings): array
    {
        return array_map(static fn (Finding $f): string => $f->id, $findings);
    }
}

#[PublicRoute(reason: 'Ticket checkout')]
final class Checkout
{
    #[VerifyHuman(action: 'checkout', minimumScore: 0.5)]
    public function pay(): string
    {
        return 'paid';
    }
}

final class ThrowingVerifier implements BotVerifierInterface
{
    public function field(): string
    {
        return 'bot_token';
    }

    public function scores(): bool
    {
        return false;
    }

    public function verify(string $token, ?string $clientIp = null, ?string $action = null): BotVerdict
    {
        throw new \RuntimeException('connection refused');
    }
}
