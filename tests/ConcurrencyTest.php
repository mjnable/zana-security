<?php

declare(strict_types=1);

namespace Zana\Security\Tests;

use PHPUnit\Framework\TestCase;
use Psr\SimpleCache\CacheInterface;
use Zana\Cache\ArrayCache as ZanaArrayCache;
use Zana\Cache\FileCache;
use Zana\Container\Contracts\ServiceCollectionInterface;
use Zana\Core\Application;
use Zana\Core\ApplicationInterface;
use Zana\Core\Inspection\ApplicationCheck;
use Zana\Core\Inspection\Finding;
use Zana\Core\Inspection\Severity;
use Zana\Http\HttpServiceProvider;
use Zana\Routing\Router;
use Zana\Routing\RoutingServiceProvider;
use Zana\Security\CsrfTokens;
use Zana\Security\Inspection\AtomicCacheCheck;
use Zana\Security\RateLimit\RateLimiter;
use Zana\Security\SecurityServiceProvider;
use Zana\Security\TokenSigner;

/**
 * 2.26, S34 and S35: rate limits and single-use tokens hold for requests at
 * the same instant, on a cache that can add and count atomically. Before,
 * twenty processes at once all passed a limit of five, and one token was
 * accepted up to six times.
 */
final class ConcurrencyTest extends TestCase
{
    private int $now = 1_800_000_000;

    public function testTwentyAtOncePassALimitOfFiveOnlyFiveTimes(): void
    {
        $this->assertSame(5, $this->race('limit', 20), 'S34: twenty passed before');
        $this->assertSame(1, $this->race('token', 20), 'S35: up to six were accepted before');
    }

    public function testOnAnAtomicCacheTheLimiterCountsAsBefore(): void
    {
        $limiter = new RateLimiter(new ZanaArrayCache(clock: fn (): int => $this->now), fn (): int => $this->now);

        $results = array_map(static fn (): array => [$limiter->attempt('k', 3, 60)->allowed, $limiter->attempt('k2', 3, 60)->remaining], range(1, 4));
        $this->assertSame([[true, 2], [true, 1], [true, 0], [false, 0]], $results, 'allowed, then refused; remaining as before');
        $this->assertFalse($limiter->attempt('k', 3, 60)->allowed, 'a refused attempt is not counted, so the count stays at the limit');
        $this->assertTrue($limiter->peek('k', 4, 60)->allowed, 'three counted, not five: refused attempts took their count back');

        $this->now += 60;
        $this->assertTrue($limiter->attempt('k', 3, 60)->allowed, 'a new window');
    }

    /**
     * The atomic path decides exactly as the read-then-write path does, one
     * request at a time: the same attempts, at the same moments, in both
     * strategies, across window edges, give the same answers and remainders.
     *
     * @param 'fixed'|'sliding' $strategy
     */
    #[\PHPUnit\Framework\Attributes\TestWith(['fixed'])]
    #[\PHPUnit\Framework\Attributes\TestWith(['sliding'])]
    public function testTheAtomicPathAnswersAsBeforeOneAtATime(string $strategy): void
    {
        $steps = [0, 3, 7, 7, 20, 31, 45, 50, 58, 61, 64, 70, 95, 119, 121, 122, 150, 181, 182, 240, 301];
        $answers = [];
        foreach (['before' => new ArrayCache(), 'atomic' => null] as $path => $cache) {
            $this->now = 1_800_000_000 - (1_800_000_000 % 60);
            $clock = fn (): int => $this->now;
            $limiter = new RateLimiter($cache ?? new ZanaArrayCache(clock: $clock), $clock);
            $start = $this->now;
            foreach ($steps as $at) {
                $this->now = $start + $at;
                $result = $limiter->attempt('k', 3, 60, $strategy);
                $answers[$path][] = ($result->allowed ? 'y' : 'n') . $result->remaining;
            }
        }

        $this->assertSame($answers['before'], $answers['atomic']);
        $this->assertContains('n0', $answers['atomic'], 'the limit was reached along the way');
    }

    public function testASingleUseTokenOnAnAtomicCache(): void
    {
        $tokens = new CsrfTokens(new TokenSigner(str_repeat('k', 32)), new ZanaArrayCache(), singleUse: true);
        $token = $tokens->issue('contact');

        $this->assertTrue($tokens->verify($token, 'contact'));
        $this->assertFalse($tokens->verify($token, 'contact'), 'once');
        $this->assertFalse($tokens->verify($tokens->issue('contact'), 'other'), 'another form, refused before it is used up');
    }

    // ── check ──────────────────────────────────────────────────────────────

    public function testCheckWarnsWhenLimitsRelyOnACacheThatCannotCount(): void
    {
        $limited = static fn (Router $r) => $r->post('/contact', [LimitedController::class, 'send']);

        $findings = $this->check(new ArrayCache(), $limited);
        $this->assertCount(1, $findings);
        $this->assertSame(['security.atomic_cache', Severity::Warning, true], [$findings[0]->id, $findings[0]->severity, $findings[0]->security]);
        $this->assertStringContainsString('(' . ArrayCache::class . ') cannot add or count atomically, so requests at the same instant can all pass rate limits (#[RateLimit])', $findings[0]->message);

        $this->assertStringContainsString('single-use CSRF tokens', $this->check(new ArrayCache(), null, ['security.csrf.single_use' => true])[0]->message);
        $this->assertSame([], $this->check(new ZanaArrayCache(), $limited), 'a Zana store counts atomically');
        // mj-zana/session is installed here, so sign-in is registered, and its attempt limit relies on the cache.
        $signIn = $this->check(new ArrayCache(), null);
        $this->assertCount(1, $signIn);
        $this->assertStringContainsString('can all pass the limit on sign-in attempts:', $signIn[0]->message);
        $this->assertSame([], $this->check(null, $limited), 'no cache');
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    /**
     * Runs $n processes that act at the same instant on one FileCache.
     *
     * @param 'limit'|'token' $mode A rate limit of 5, or one single-use token
     * @return int How many passed
     */
    private function race(string $mode, int $n): int
    {
        $directory = sys_get_temp_dir() . '/zana-security-race-' . bin2hex(random_bytes(4));
        $token = (new CsrfTokens(new TokenSigner(str_repeat('k', 32))))->issue();
        $start = microtime(true) + 2;
        $processes = [];
        $pipes = [];
        for ($i = 0; $i < $n; $i++) {
            $process = proc_open([PHP_BINARY, '-d', 'xdebug.mode=off', __DIR__ . '/Fixtures/race.php', $mode, $directory, (string) $start, $token], [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes[$i]);
            $this->assertIsResource($process);
            $processes[$i] = $process;
        }
        $passed = 0;
        foreach ($processes as $i => $process) {
            $out = (string) stream_get_contents($pipes[$i][1]);
            $errors = (string) stream_get_contents($pipes[$i][2]);
            proc_close($process);
            $this->assertSame('', $errors);
            $this->assertMatchesRegularExpression('/^\[[YN]\]$/', $out, 'each process answered');
            $passed += $out === '[Y]' ? 1 : 0;
        }
        (new FileCache($directory))->clear();
        @array_map('rmdir', glob("{$directory}/*", GLOB_ONLYDIR) ?: []);
        @rmdir($directory);

        return $passed;
    }

    /**
     * @param array<string, mixed> $config
     * @return list<Finding>
     */
    private function check(?CacheInterface $cache, ?\Closure $routes, array $config = []): array
    {
        $app = Application::configure(sys_get_temp_dir() . '/zana-security-atomic')
            ->withEnvironment('testing')
            ->withConfiguration(['security.secret' => str_repeat('s', 40), ...$config])
            ->withProviders(HttpServiceProvider::class, RoutingServiceProvider::class, SecurityServiceProvider::class)
            ->withServices(static function (ServiceCollectionInterface $s) use ($cache): void {
                if ($cache !== null) {
                    $s->singleton(CacheInterface::class, static fn (): CacheInterface => $cache);
                }
            })
            ->build();
        if ($routes !== null) {
            $router = $app->container()->get(Router::class);
            assert($router instanceof Router);
            $routes($router);
        }

        return self::findingsOf($app);
    }

    /**
     * @return list<Finding>
     */
    private static function findingsOf(ApplicationInterface $app): array
    {
        foreach ($app->container()->tagged(ApplicationCheck::TAG) as $check) {
            if ($check instanceof AtomicCacheCheck) {
                return $check->findings($app);
            }
        }
        self::fail('AtomicCacheCheck is not tagged.');
    }
}
