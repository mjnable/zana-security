<?php

declare(strict_types=1);

namespace Zana\Security\Tests;

use PHPUnit\Framework\TestCase;
use Zana\Events\EventDispatcher;
use Zana\Events\ListenerProvider;
use Zana\Http\Exception\TooManyRequestsHttpException;
use Zana\Security\Event\PasswordResetRequested;
use Zana\Security\Event\PasswordResetTokenUsed;
use Zana\Security\Event\SecurityEvent;
use Zana\Security\Event\SignedOut;
use Zana\Security\Event\SignInFailed;
use Zana\Security\Event\SignInSucceeded;
use Zana\Security\PasswordHasher;
use Zana\Security\PasswordResetTokens;
use Zana\Security\RateLimit\RateLimiter;
use Zana\Security\SecurityContext;
use Zana\Security\Session\SessionLogin;
use Zana\Security\TokenSigner;
use Zana\Session\Session;

/**
 * FE-58 (2.15): sign-ins, sign-outs and password resets are dispatched as
 * SecurityEvents when an event dispatcher is given; without one, nothing
 * changes.
 */
final class SecurityEventsTest extends TestCase
{
    /** @var list<SecurityEvent> */
    private array $events = [];

    public function testSignInsAndSignOutsAreDispatched(): void
    {
        $hasher = new PasswordHasher(['cost' => 4], PASSWORD_BCRYPT);
        $login = new SessionLogin(new LoginUsers($hasher->hash('secret-pass')), $hasher, new Session(), new SecurityContext(), new RateLimiter(new ArrayCache()), maxAttempts: 2, events: $this->dispatcher());

        $this->assertNull($login->attempt('ada@example.com', 'wrong', '198.51.100.7'));
        $this->assertNotNull($login->attempt('ada@example.com', 'secret-pass', '198.51.100.7'));
        $login->logout('198.51.100.7');
        $login->logout('198.51.100.7');   // nobody is signed in: no event

        $this->assertEquals([
            new SignInFailed('ada@example.com', SignInFailed::INVALID_CREDENTIALS, '198.51.100.7'),
            new SignInSucceeded('1', '198.51.100.7'),
            new SignedOut('1', '198.51.100.7'),
        ], $this->events);
        $this->assertSame(['security.sign_in_failed', 'security.sign_in', 'security.sign_out'], array_map(static fn (SecurityEvent $e): string => $e->action(), $this->events));
    }

    public function testThrottledAttemptsAreDispatchedToo(): void
    {
        $hasher = new PasswordHasher(['cost' => 4], PASSWORD_BCRYPT);
        $login = new SessionLogin(new LoginUsers($hasher->hash('secret-pass')), $hasher, new Session(), new SecurityContext(), new RateLimiter(new ArrayCache()), maxAttempts: 1, events: $this->dispatcher());

        $login->attempt('nobody@example.com', 'guess', '203.0.113.9');
        try {
            $login->attempt('nobody@example.com', 'guess', '203.0.113.9');
            $this->fail('The second attempt is throttled.');
        } catch (TooManyRequestsHttpException) {
        }

        $this->assertEquals([
            new SignInFailed('nobody@example.com', SignInFailed::INVALID_CREDENTIALS, '203.0.113.9'),
            new SignInFailed('nobody@example.com', SignInFailed::THROTTLED, '203.0.113.9'),
        ], $this->events);
    }

    public function testPasswordResetsAreDispatched(): void
    {
        $hasher = new PasswordHasher(['cost' => 4], PASSWORD_BCRYPT);
        $users = new LoginUsers($hasher->hash('secret-pass'));
        $resets = new PasswordResetTokens(new TokenSigner(str_repeat('k', 32)), new ArrayCache(), $users, events: $this->dispatcher());

        $token = $resets->issue(new BackOfficeUser());
        $this->assertNotNull($resets->check($token), 'checking does not use it');
        $this->assertNotNull($resets->consume($token));
        $this->assertNull($resets->consume($token), 'used up: no second event');

        $this->assertEquals([new PasswordResetRequested('1'), new PasswordResetTokenUsed('1')], $this->events);
    }

    private function dispatcher(): EventDispatcher
    {
        return new EventDispatcher((new ListenerProvider())->listen(SecurityEvent::class, function (SecurityEvent $event): void {
            $this->events[] = $event;
        }));
    }
}
