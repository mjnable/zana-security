<?php

declare(strict_types=1);

namespace Zana\Security\Tests;

use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\EventDispatcher\EventDispatcherInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\SimpleCache\CacheInterface;
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
use Zana\Security\Attribute\SpamRules;
use Zana\Security\Event\SpamRefused;
use Zana\Security\Inspection\SpamRulesCheck;
use Zana\Security\Middleware\SpamGuardMiddleware;
use Zana\Security\SecurityException;
use Zana\Security\SecurityServiceProvider;
use Zana\Security\Spam\Rule\BlockedTerms;
use Zana\Security\Spam\Rule\FixedScore;
use Zana\Security\Spam\Rule\RepeatedContent;
use Zana\Security\Spam\Rule\TooManyLinks;
use Zana\Security\Spam\Signal;
use Zana\Security\Spam\SpamGuard;
use Zana\Security\Spam\SpamRuleInterface;
use Zana\Security\Spam\Submission;

/**
 * 2.24, FE-63: spam rules per form, beside the honeypot: too many links,
 * blocked terms, the same text sent again, and the application's own rules.
 */
final class SpamRulesTest extends TestCase
{
    private int $now = 1_800_000_000;

    // ── The rules ──────────────────────────────────────────────────────────

    public function testLinks(): void
    {
        $rule = new TooManyLinks(2);

        $this->assertNull($rule->check(self::sent('See https://a.example and www.b.example')));
        $signal = $rule->check(self::sent('https://a.example [url=x]x[/url] <a href="y">y</a>'));
        $this->assertNotNull($signal);
        $this->assertSame('3 link(s), at most 2', $signal->reason);
        $this->assertNotNull((new TooManyLinks(0))->check(self::sent('HTTP://SHOUTED.EXAMPLE')), 'whatever the case');
        $this->assertNotNull($rule->check(new Submission('contact', ['a' => 'https://1 https://2', 'b' => 'https://3'], 'ip:x')), 'across the fields');
    }

    public function testBlockedTermsAreWholeWordsWhateverTheirCaseAndSpacing(): void
    {
        $rule = new BlockedTerms(['casino', 'crypto investment', 'a/b']);

        foreach (['Best CASINO!', 'casino.', 'Crypto   Investment now', "crypto\ninvestment", "ca\u{200B}sino", 'a/b'] as $spam) {
            $this->assertNotNull($rule->check(self::sent($spam)), $spam);
        }
        foreach (['I go occasionally', 'casinos', 'cryptoinvestment', 'crypto, investment', 'a b'] as $fine) {
            $this->assertNull($rule->check(self::sent($fine)), $fine);
        }
        $this->assertSame('blocked term(s): casino, crypto investment', $rule->check(self::sent('casino crypto investment'))?->reason);
    }

    public function testTheSameTextAgainFromTheSameClientWithinTheWindow(): void
    {
        $rule = new RepeatedContent(new SpamCache(), 10, now: fn (): int => $this->now);
        $first = self::sent('Hello, I would like a quote.');

        $this->assertNull($rule->check($first), 'never sent before');
        $rule->accepted($first);
        $this->assertNotNull($rule->check(self::sent("  HELLO,   i would like a quote.\n")), 'the same text, typed otherwise');
        $this->assertNull($rule->check(self::sent('Hello, I would like a quote.', client: 'ip:203.0.113.9')), 'another client');
        $this->assertNull($rule->check(new Submission('newsletter', $first->fields, $first->client)), 'another form');
        $this->assertNull($rule->check(self::sent('Hello, I would like two quotes.')), 'other text');

        $this->now += 10 * 60;
        $this->assertNull($rule->check($first), 'after the window');
    }

    public function testRepeatedContentForEveryoneAndNotForAnEmptyForm(): void
    {
        $everyone = new RepeatedContent(new SpamCache(), 10, 'everyone', fn (): int => $this->now);
        $everyone->accepted(self::sent('Buy now'));
        $this->assertNotNull($everyone->check(self::sent('Buy now', client: 'ip:203.0.113.9')), 'from any client');

        $rule = new RepeatedContent(new SpamCache(), 10, now: fn (): int => $this->now);
        $rule->accepted(self::sent(' '));
        $this->assertNull($rule->check(self::sent(' ')), 'an empty form is not a message');
    }

    public function testOnlyAHashIsKept(): void
    {
        $cache = new SpamCache();
        (new RepeatedContent($cache, 10, now: fn (): int => $this->now))->accepted(self::sent('My phone is 0812345678'));

        $this->assertCount(1, $cache->values);
        $key = (string) array_key_first($cache->values);
        $this->assertMatchesRegularExpression('/^zana_spam_[0-9a-f]{64}$/', $key, 'a valid PSR-16 key, without the text');
        $this->assertStringNotContainsString('0812345678', serialize($cache->values));
    }

    public function testPointsAddUpToTheThreshold(): void
    {
        $guard = $this->guard(['contact' => ['max_links' => 0, 'blocked_terms' => ['casino'], 'threshold' => 2]]);

        $this->assertFalse($guard->judge('contact', self::sent('https://a.example'))->spam, 'one rule: 1 point of 2');
        $verdict = $guard->judge('contact', self::sent('casino at https://a.example'));
        $this->assertTrue($verdict->spam);
        $this->assertSame([2, 2], [$verdict->points, $verdict->threshold]);
        $this->assertSame(['links: 1 link(s), at most 0', 'blocked_terms: blocked term(s): casino'], $verdict->reasons());
    }

    public function testAnApplicationRuleFromTheContainerOrCreated(): void
    {
        $created = [];
        $guard = new SpamGuard(['contact' => ['rules' => [NoShouting::class]]], null, static function (string $class) use (&$created): SpamRuleInterface {
            $created[] = $class;

            return new $class();
        });

        $this->assertTrue($guard->judge('contact', self::sent('PLEASE CALL ME BACK ABOUT THE OFFER RIGHT NOW!!!'))->spam);
        $this->assertFalse($guard->judge('contact', self::sent('Please call me back.'))->spam);
        $this->assertSame([NoShouting::class], $created, 'created once per guard');
    }

    public function testFixedScoreForTests(): void
    {
        $this->assertTrue($this->guard(['contact' => ['rules' => [FixedScore::class]]])->judge('contact', self::sent('anything'))->spam);
        $this->assertNull((new FixedScore(0))->check(self::sent('anything')));
    }

    // ── The middleware ─────────────────────────────────────────────────────

    public function testASpamPostIsRefusedWithoutReachingTheHandler(): void
    {
        $events = new RecordingDispatcher();
        $handler = new Answer();
        $middleware = new SpamGuardMiddleware($this->guard(['contact' => ['max_links' => 1]]), events: $events);

        try {
            $middleware->process(self::post(['message' => 'https://a https://b']), $handler);
            self::fail('Spam was accepted.');
        } catch (ForbiddenHttpException $e) {
            $this->assertSame('The form could not be accepted.', $e->getMessage(), 'the same words as a filled honeypot');
        }
        $this->assertSame(0, $handler->calls);
        $this->assertCount(1, $events->events);
        $event = $events->events[0];
        $this->assertInstanceOf(SpamRefused::class, $event);
        $this->assertSame(['contact', ['links: 2 link(s), at most 1'], 1, '198.51.100.7'], [$event->form, $event->reasons, $event->points, $event->clientIp]);
        $this->assertSame('security.spam_refused', $event->action());
        $this->assertStringNotContainsString('https://a', serialize($event), 'never the text');

        $this->assertSame(200, $middleware->process(self::post(['message' => 'https://a']), $handler)->getStatusCode());
        $this->assertSame(1, $handler->calls);
    }

    public function testSpamIsSentToTheRedirectAsIfItSucceeded(): void
    {
        $post = self::post(['message' => 'https://a https://b']);

        $global = (new SpamGuardMiddleware($this->guard(['contact' => ['max_links' => 1]]), spamRedirect: '/thanks'))->process($post, new Answer());
        $this->assertSame([303, '/thanks'], [$global->getStatusCode(), $global->getHeaderLine('Location')]);

        $own = (new SpamGuardMiddleware($this->guard(['contact' => ['max_links' => 1, 'redirect' => '/en/contact/thanks']]), spamRedirect: '/thanks'))->process($post, new Answer());
        $this->assertSame('/en/contact/thanks', $own->getHeaderLine('Location'), "the form's own first");
    }

    public function testTheTokenTheFormNameAndTheHoneypotAreNotRead(): void
    {
        $middleware = new SpamGuardMiddleware($this->guard(['contact' => ['max_links' => 0]]), honeypot: 'website');

        $response = $middleware->process(self::post(['_token' => 'https://x', '_form' => 'https://y', 'website' => 'https://z', 'message' => 'Hello']), new Answer());

        $this->assertSame(200, $response->getStatusCode());
    }

    public function testOnlyTheFieldsNamed(): void
    {
        $middleware = new SpamGuardMiddleware($this->guard(['contact' => ['max_links' => 0, 'fields' => ['message']]]));

        $this->assertSame(200, $middleware->process(self::post(['website_url' => 'https://my.example', 'message' => 'Hello']), new Answer())->getStatusCode());
        $this->expectException(ForbiddenHttpException::class);
        $middleware->process(self::post(['message' => ['Hello', 'https://x']]), new Answer());   // a list field by its name
    }

    public function testAcceptedTextIsRememberedOnlyWhenTheHandlerSucceeds(): void
    {
        $guard = $this->guard(['contact' => ['duplicate_minutes' => 10]], new SpamCache());
        $middleware = new SpamGuardMiddleware($guard);
        $post = self::post(['email' => 'ada@example', 'message' => 'Please call me']);

        $this->assertSame(422, $middleware->process($post, new Answer(422))->getStatusCode(), 'the form shown again with an error');
        $this->assertSame(200, $middleware->process($post, new Answer())->getStatusCode(), 'the corrected form, the same message: accepted');
        $this->expectException(ForbiddenHttpException::class);
        $middleware->process($post, new Answer());   // and once more: a repeat
    }

    public function testNotOnAGetNorWithoutTheAttribute(): void
    {
        $middleware = new SpamGuardMiddleware($this->guard(['contact' => ['rules' => [FixedScore::class]]]));

        $this->assertSame(200, $middleware->process(self::post([], 'GET'), new Answer())->getStatusCode());
        $this->assertSame(200, $middleware->process(self::post(['m' => 'x'])->withAttribute('_handler', [UnguardedForm::class, 'send']), new Answer())->getStatusCode());
        $this->assertSame(200, $middleware->process(self::post(['m' => 'x'])->withAttribute('_handler', null), new Answer())->getStatusCode());
    }

    public function testASignedInUserIsTheClient(): void
    {
        $this->assertSame('user:42', Submission::fromRequest(self::post(['m' => 'x']), 'contact', userId: '42')->client);
        $this->assertSame('ip:203.0.113.5', Submission::fromRequest(self::post(['m' => 'x'])->withAttribute('client_ip', '203.0.113.5'), 'contact')->client, 'behind a trusted proxy');
    }

    public function testAFormWithoutRulesFailsClosed(): void
    {
        $this->expectException(SecurityException::class);
        $this->expectExceptionMessage("#[SpamRules('contact')] names a form without rules");
        (new SpamGuardMiddleware($this->guard([])))->process(self::post(['m' => 'x']), new Answer());
    }

    public function testHostileBodiesAreRead(): void
    {
        $middleware = new SpamGuardMiddleware($this->guard(['contact' => ['max_links' => 2, 'blocked_terms' => ['casino']]]));
        $deep = 'x';
        for ($i = 0; $i < 200; $i++) {
            $deep = [$deep];
        }

        foreach ([['message' => str_repeat('a ', 1_000_000)], ['message' => $deep], ['message' => "\xff\xfe invalid UTF-8"], ['m' => ['a' => ['b' => 'casino']]], [7 => 'casino']] as $n => $body) {
            try {
                $middleware->process(self::post($body), new Answer());
            } catch (ForbiddenHttpException) {
                // refused as spam: fine
            }
            $this->addToAssertionCount(1);   // no error, no warning (PHPUnit fails on either)
            unset($n);
        }
    }

    // ── Settings, and check ────────────────────────────────────────────────

    /**
     * @return iterable<string, array{0: mixed, 1: string}>
     */
    public static function badSettings(): iterable
    {
        yield 'an unknown setting' => [['max_link' => 2], 'has an unknown setting "max_link"'];
        yield 'no rule' => [['threshold' => 1], 'sets no rule, so it refuses nothing'];
        yield 'not a list' => ['yes', 'is not a list of settings'];
        yield 'negative links' => [['max_links' => -1], 'max_links is -1, not a whole number of at least 0'];
        yield 'links as text' => [['max_links' => '2'], 'max_links is "2"'];
        yield 'zero minutes' => [['duplicate_minutes' => 0], 'duplicate_minutes is 0'];
        yield 'threshold zero' => [['max_links' => 1, 'threshold' => 0], 'threshold is 0'];
        yield 'terms not a list' => [['blocked_terms' => 'casino'], 'blocked_terms is not a list of names'];
        yield 'an empty term' => [['blocked_terms' => ['casino', ' ']], 'blocked_terms is not a list of names'];
        yield 'a scope' => [['duplicate_minutes' => 5, 'duplicate_scope' => 'world'], 'duplicate_scope is "world"'];
        yield 'a rule that is not one' => [['rules' => [\stdClass::class]], 'rules names stdClass, which is not a class implementing'];
        yield 'a missing rule class' => [['rules' => ['App\Nope']], 'rules names App\Nope'];
        yield 'a redirect to another site' => [['max_links' => 1, 'redirect' => 'https://evil.example/'], 'redirect must be a path on this site'];
        yield 'a protocol-relative redirect' => [['max_links' => 1, 'redirect' => '//evil.example/'], 'redirect must be a path on this site'];
        yield 'a backslash redirect' => [['max_links' => 1, 'redirect' => '/\evil.example'], 'redirect must be a path on this site'];
    }

    #[DataProvider('badSettings')]
    public function testSettingsThatCannotBeUsedAreReportedAndRefuseToRun(mixed $settings, string $problem): void
    {
        $findings = $this->check(['security.spam.forms' => ['contact' => $settings]], strict: true);

        $this->assertNotSame([], $findings);
        $this->assertSame('security.spam_rules', $findings[0]->id);
        $this->assertSame(Severity::Error, $findings[0]->severity);
        $this->assertStringContainsString($problem, $findings[0]->message);
        $this->assertTrue($findings[0]->security);

        $this->expectException(SecurityException::class);
        $this->guard(['contact' => $settings])->judge('contact', self::sent('x'));
    }

    public function testDuplicatesWithoutACacheAreReported(): void
    {
        $findings = $this->check(['security.spam.forms' => ['contact' => ['duplicate_minutes' => 10]]], strict: true);

        $this->assertSame(['security.spam_rules'], array_values(array_unique(array_map(static fn (Finding $f): string => $f->id, $findings))));
        $this->assertStringContainsString('duplicate_minutes needs a PSR-16 cache', $findings[0]->message);
    }

    public function testGoodSettingsAreQuiet(): void
    {
        $this->assertSame([], $this->check(['security.spam.forms' => ['contact' => ['max_links' => 2, 'blocked_terms' => ['casino'], 'fields' => ['message'], 'rules' => [NoShouting::class], 'threshold' => 1, 'redirect' => '/thanks']]], strict: true));
    }

    public function testCheckReportsRulesNothingEnforces(): void
    {
        $forms = ['security.spam.forms' => ['contact' => ['max_links' => 2]]];
        $findings = $this->check($forms, static function (Router $r): void {
            $r->post('/contact', [GuardedForm::class, 'send']);                                          // no middleware
            $r->post('/guarded', [GuardedForm::class, 'send'])->middleware(SpamGuardMiddleware::class);  // fine
            $r->post('/newsletter', [OtherForm::class, 'send'])->middleware(SpamGuardMiddleware::class); // no rules for it
            $r->get('/contact', [GuardedForm::class, 'send'])->middleware(SpamGuardMiddleware::class);   // never read
        }, strict: true);

        $this->assertSame([
            'Error POST /contact has #[SpamRules(\'contact\')], but SpamGuardMiddleware is not on the route, so its rules refuse nothing.',
            'Error POST /newsletter has #[SpamRules(\'newsletter\')], but security.spam.forms has no "newsletter": the form has no rules, and every post to it fails.',
            'Warning GET /contact has #[SpamRules(\'contact\')], but receives no POST, PUT or PATCH, which is all the rules read.',
        ], array_map(static fn (Finding $f): string => "{$f->severity->name} {$f->message}", $findings));
        $this->assertSame(Severity::Warning, $this->check($forms, static fn (Router $r) => $r->post('/contact', [GuardedForm::class, 'send']))[0]->severity, 'a warning unless strict');
    }

    public function testTheMiddlewareInHttpMiddlewareIsReported(): void
    {
        $findings = $this->check(['security.spam.forms' => ['contact' => ['max_links' => 2]], 'http.middleware' => [SpamGuardMiddleware::class]], static fn (Router $r) => $r->post('/contact', [GuardedForm::class, 'send'])->middleware(SpamGuardMiddleware::class), strict: true, all: true);

        $global = array_values(array_filter($findings, static fn (Finding $f): bool => $f->id === 'security.global_middleware'));
        $this->assertCount(1, $global);
        $this->assertStringContainsString('SpamGuardMiddleware is in http.middleware', $global[0]->message);
    }

    public function testTheApplicationWiresTheGuard(): void
    {
        $app = $this->app(['security.spam.forms' => ['contact' => ['rules' => [FixedScore::class]]], 'security.csrf.spam_redirect' => '/thanks']);

        $middleware = $app->container()->createScope()->get(SpamGuardMiddleware::class);
        $this->assertInstanceOf(SpamGuardMiddleware::class, $middleware);
        $response = $middleware->process(self::post(['m' => 'x']), new Answer());
        $this->assertSame([303, '/thanks'], [$response->getStatusCode(), $response->getHeaderLine('Location')]);
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    private static function sent(string $text, string $client = 'ip:198.51.100.7'): Submission
    {
        return new Submission('contact', ['message' => $text], $client);
    }

    /**
     * @param array<mixed> $body
     */
    private static function post(array $body, string $method = 'POST'): ServerRequestInterface
    {
        return (new ServerRequest($method, '/contact', serverParams: ['REMOTE_ADDR' => '198.51.100.7']))
            ->withParsedBody($body)
            ->withAttribute('_handler', [GuardedForm::class, 'send']);
    }

    /**
     * @param array<mixed> $forms
     */
    private function guard(array $forms, ?CacheInterface $cache = null): SpamGuard
    {
        return new SpamGuard($forms, $cache, static fn (string $class): SpamRuleInterface => new $class(), fn (): int => $this->now);
    }

    /**
     * @param array<string, mixed> $config
     */
    private function app(array $config): ApplicationInterface
    {
        return Application::configure(sys_get_temp_dir() . '/zana-security-spam')
            ->withEnvironment('testing')
            ->withConfiguration(['security.secret' => str_repeat('s', 40), ...$config])
            ->withProviders(HttpServiceProvider::class, RoutingServiceProvider::class, SecurityServiceProvider::class)
            ->build();
    }

    /**
     * @param array<string, mixed> $config
     * @return list<Finding>
     */
    private function check(array $config, ?\Closure $routes = null, bool $strict = false, bool $all = false): array
    {
        $app = $this->app(['security.strict' => $strict, ...$config]);
        if ($routes !== null) {
            $router = $app->container()->get(Router::class);
            assert($router instanceof Router);
            $routes($router);
        }
        $findings = [];
        foreach ($app->container()->tagged(ApplicationCheck::TAG) as $check) {
            if ($check instanceof SpamRulesCheck || ($all && $check instanceof ApplicationCheck)) {
                array_push($findings, ...$check->findings($app));
            }
        }

        return $findings;
    }
}

#[PublicRoute(reason: 'The contact form')]
final class GuardedForm
{
    #[SpamRules('contact')]
    public function send(): string
    {
        return 'sent';
    }
}

#[PublicRoute(reason: 'The newsletter form')]
final class OtherForm
{
    #[SpamRules('newsletter')]
    public function send(): string
    {
        return 'sent';
    }
}

final class UnguardedForm
{
    public function send(): string
    {
        return 'sent';
    }
}

final class NoShouting implements SpamRuleInterface
{
    public function check(Submission $submission): ?Signal
    {
        $text = $submission->text();

        return strlen($text) > 20 && strtoupper($text) === $text ? new Signal('shouting', 1, 'all in capitals') : null;
    }
}

final class Answer implements RequestHandlerInterface
{
    public int $calls = 0;

    public function __construct(private readonly int $status = 200)
    {
    }

    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $this->calls++;

        return new Response($this->status);
    }
}

final class RecordingDispatcher implements EventDispatcherInterface
{
    /** @var list<object> */
    public array $events = [];

    public function dispatch(object $event): object
    {
        $this->events[] = $event;

        return $event;
    }
}

final class SpamCache implements CacheInterface
{
    /** @var array<string, mixed> */
    public array $values = [];

    public function get(string $key, mixed $default = null): mixed
    {
        return $this->values[$key] ?? $default;
    }

    public function set(string $key, mixed $value, \DateInterval|int|null $ttl = null): bool
    {
        $this->values[$key] = $value;

        return true;
    }

    public function delete(string $key): bool
    {
        unset($this->values[$key]);

        return true;
    }

    public function clear(): bool
    {
        $this->values = [];

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
        return array_key_exists($key, $this->values);
    }
}
