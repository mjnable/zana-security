<?php

declare(strict_types=1);

namespace Zana\Security\Tests;

use PHPUnit\Framework\TestCase;
use Zana\Events\EventDispatcher;
use Zana\Events\ListenerProvider;
use Zana\Http\Exception\TooManyRequestsHttpException;
use Zana\Security\Event\RecoveryCodeUsed;
use Zana\Security\Event\SecurityEvent;
use Zana\Security\Event\SignInSucceeded;
use Zana\Security\Event\TwoFactorDisabled;
use Zana\Security\Event\TwoFactorEnabled;
use Zana\Security\Event\TwoFactorFailed;
use Zana\Security\Internal\Base32;
use Zana\Security\Internal\SecretBox;
use Zana\Security\PasswordHasher;
use Zana\Security\RateLimit\RateLimiter;
use Zana\Security\SecurityContext;
use Zana\Security\SecurityException;
use Zana\Security\Session\LoginResult;
use Zana\Security\Session\SessionLogin;
use Zana\Security\TokenSigner;
use Zana\Security\TwoFactor\OneTimeCodes;
use Zana\Security\TwoFactor\Totp;
use Zana\Security\TwoFactor\TwoFactor;
use Zana\Security\TwoFactorUserProviderInterface;
use Zana\Security\UserInterface;
use Zana\Session\Session;

final class TwoFactorUsers implements TwoFactorUserProviderInterface, \Zana\Security\PasswordUserProviderInterface
{
    public ?string $state = null;

    private BackOfficeUser $staff;

    public function __construct(public string $hash)
    {
        $this->staff = new BackOfficeUser();
    }

    public function findByIdentifier(string $identifier): ?UserInterface
    {
        return $identifier === '1' ? $this->staff : null;
    }

    public function findByLogin(string $login): ?UserInterface
    {
        return $login === 'ada@example.com' ? $this->staff : null;
    }

    public function passwordHashFor(UserInterface $user): string
    {
        return $this->hash;
    }

    public function twoFactorStateFor(UserInterface $user): ?string
    {
        return $this->state;
    }

    public function saveTwoFactorState(UserInterface $user, ?string $state): void
    {
        $this->state = $state;
    }
}

/**
 * FE-56, ADR-031: TOTP (RFC 6238), recovery codes, the second sign-in step,
 * remembered devices and one-time codes.
 */
final class TwoFactorTest extends TestCase
{
    private int $now = 1_800_000_000;

    /** @var list<SecurityEvent> */
    private array $events = [];

    private TwoFactorUsers $users;

    private ArrayCache $cache;

    protected function setUp(): void
    {
        $this->users = new TwoFactorUsers((new PasswordHasher(['cost' => 4], PASSWORD_BCRYPT))->hash('secret-pass'));
        $this->cache = new ArrayCache();
    }

    public function testTotpMatchesTheRfc6238TestVectors(): void
    {
        $secret = Base32::encode('12345678901234567890');
        $this->assertSame('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', $secret);
        $this->assertSame('12345678901234567890', Base32::decode($secret));

        $at = static fn (int $time): string => (new Totp(static fn (): int => $time))->code($secret);
        // The RFC's 8-digit values are 94287082, 07081804, 14050471 and 89005924; apps show the last six.
        $this->assertSame(['287082', '081804', '050471', '005924'], [$at(59), $at(1111111109), $at(1111111111), $at(1234567890)]);
    }

    public function testACodeWorksOnceAndOneStepEarlyOrLate(): void
    {
        $totp = new Totp(fn (): int => $this->now);
        $secret = $totp->generateSecret();
        $step = $totp->currentStep();

        $this->assertSame($step, $totp->verify($secret, $totp->code($secret, $step)));
        $this->assertSame($step - 1, $totp->verify($secret, $totp->code($secret, $step - 1)), 'one step late');
        $this->assertSame($step + 1, $totp->verify($secret, $totp->code($secret, $step + 1)), 'one step early');
        $this->assertNull($totp->verify($secret, $totp->code($secret, $step - 2)), 'outside its window');
        $this->assertNull($totp->verify($secret, $totp->code($secret, $step), lastUsedStep: $step), 'already used');
        $this->assertNull($totp->verify($secret, 'abc123'));
        $this->assertStringStartsWith('otpauth://totp/Billets%20RDC:ada%40example.com?secret=' . $secret . '&issuer=Billets%20RDC', $totp->uri($secret, 'Billets RDC', 'ada@example.com'));
    }

    public function testEnrolConfirmVerifyAndDisable(): void
    {
        $twoFactor = $this->twoFactor();
        $user = new BackOfficeUser();

        $enrolment = $twoFactor->enrol($user, 'ada@example.com');
        $this->assertFalse($twoFactor->enabled($user), 'not before confirmation');
        $this->assertCount(10, $enrolment->recoveryCodes);
        $this->assertStringNotContainsString($enrolment->secret, (string) $this->users->state, 'the stored state is sealed');
        $this->assertFalse($twoFactor->confirm($user, '000000'));
        $this->assertTrue($twoFactor->confirm($user, $this->code($enrolment->secret)));
        $this->assertTrue($twoFactor->enabled($user));

        $this->assertFalse($twoFactor->verify($user, $this->code($enrolment->secret)), 'the confirming code is used up');
        $this->now += 30;
        $this->assertTrue($twoFactor->verify($user, $this->code($enrolment->secret)));

        $this->assertTrue($twoFactor->verify($user, strtoupper($enrolment->recoveryCodes[3])), 'a recovery code, in any case');
        $this->assertFalse($twoFactor->verify($user, $enrolment->recoveryCodes[3]), 'once');
        $this->assertSame(9, $twoFactor->remainingRecoveryCodes($user));
        $fresh = $twoFactor->regenerateRecoveryCodes($user);
        $this->assertFalse($twoFactor->verify($user, $enrolment->recoveryCodes[4]), 'old codes stop working');
        $this->assertTrue($twoFactor->verify($user, $fresh[0]));

        try {
            $twoFactor->enrol($user);
            $this->fail('Enrolling twice would replace a working second factor.');
        } catch (SecurityException) {
        }
        $twoFactor->disable($user);
        $this->assertFalse($twoFactor->enabled($user));
        $this->assertNull($this->users->state);

        $this->assertSame(
            [TwoFactorEnabled::class, TwoFactorFailed::class, RecoveryCodeUsed::class, TwoFactorFailed::class, TwoFactorFailed::class, RecoveryCodeUsed::class, TwoFactorDisabled::class],
            array_map(static fn (object $e): string => $e::class, $this->events),
        );
    }

    public function testCodesAreRefusedAfterTheAttemptLimit(): void
    {
        $twoFactor = $this->twoFactor(maxAttempts: 3);
        $user = new BackOfficeUser();
        $secret = $twoFactor->enrol($user)->secret;
        $twoFactor->confirm($user, $this->code($secret));
        $this->now += 30;

        foreach (range(1, 3) as $_) {
            $this->assertFalse($twoFactor->verify($user, '111111'));
        }
        $this->expectException(TooManyRequestsHttpException::class);
        $twoFactor->verify($user, $this->code($secret));
    }

    public function testAStateThatCannotBeOpenedFailsClosed(): void
    {
        $twoFactor = $this->twoFactor();
        $user = new BackOfficeUser();
        $secret = $twoFactor->enrol($user)->secret;
        $twoFactor->confirm($user, $this->code($secret));
        $this->now += 30;
        $otherKey = $this->twoFactor(key: str_repeat('z', 40));

        $this->assertTrue($otherKey->enabled($user), 'a changed key must not turn the second factor off');
        $this->assertFalse($otherKey->verify($user, $this->code($secret)), 'and no code passes it');
        $last = end($this->events);
        $this->assertInstanceOf(TwoFactorFailed::class, $last);
        $this->assertSame(TwoFactorFailed::UNREADABLE, $last->reason);
        [$login, $session] = $this->login($otherKey);
        $this->assertSame(LoginResult::SECOND_FACTOR_REQUIRED, $login->start('ada@example.com', 'secret-pass')->status, 'the password alone does not sign in');
        $this->assertFalse($session->has(SessionLogin::SESSION_KEY));
        $this->assertFalse($login->completeSecondFactor($this->code($secret))->signedIn());

        $this->users->state = substr((string) $this->users->state, 0, -2) . 'AA';
        $this->assertTrue($twoFactor->enabled($user), 'a damaged state neither');
        $this->assertFalse($twoFactor->verify($user, $this->code($secret)));
        try {
            $twoFactor->enrol($user);
            $this->fail('An unreadable second factor must not be replaced by a new enrolment.');
        } catch (SecurityException $e) {
            $this->assertStringContainsString('cannot be read', $e->getMessage());
        }
        $twoFactor->disable($user);
        $this->assertFalse($twoFactor->enabled($user), 'an administrator can still disable it');

        $this->expectException(SecurityException::class);
        $this->expectExceptionMessage('security.two_factor.key must be at least 32 characters');
        new SecretBox('short');
    }

    public function testThePasswordAloneDoesNotSignInAUserWithASecondFactor(): void
    {
        $twoFactor = $this->twoFactor();
        $user = new BackOfficeUser();
        $secret = $twoFactor->enrol($user)->secret;
        $twoFactor->confirm($user, $this->code($secret));
        $this->now += 30;
        [$login, $session, $context] = $this->login($twoFactor);

        $this->assertNull($login->attempt('ada@example.com', 'secret-pass'), 'attempt() of 2.15 does not sign in');
        $this->assertTrue($login->hasPendingSecondFactor());
        $this->assertFalse($session->has(SessionLogin::SESSION_KEY), 'the session is not signed in');
        $this->assertNull($context->user());

        $this->assertSame(LoginResult::FAILED, $login->completeSecondFactor('000000')->status);
        $result = $login->completeSecondFactor($this->code($secret), '198.51.100.7');
        $this->assertTrue($result->signedIn());
        $this->assertSame('1', $result->user?->identifier());
        $this->assertSame('1', $session->get(SessionLogin::SESSION_KEY));
        $this->assertSame($user->identifier(), self::signedInId($context));
        $this->assertFalse($login->hasPendingSecondFactor());
        $signIns = array_values(array_filter($this->events, static fn (object $e): bool => $e instanceof SignInSucceeded));
        $this->assertSame('session+two_factor', $signIns[0]->method ?? null);
    }

    public function testAPendingSignInExpiresAndARememberedDeviceSkipsTheCode(): void
    {
        $twoFactor = $this->twoFactor();
        $user = new BackOfficeUser();
        $secret = $twoFactor->enrol($user)->secret;
        $twoFactor->confirm($user, $this->code($secret));
        $this->now += 30;
        [$login] = $this->login($twoFactor);

        $this->assertTrue($login->start('ada@example.com', 'secret-pass')->needsSecondFactor());
        $this->now += 301;
        $this->assertSame(LoginResult::FAILED, $login->completeSecondFactor($this->code($secret))->status, 'after 5 minutes, the password is needed again');

        $this->assertTrue($login->start('ada@example.com', 'secret-pass')->needsSecondFactor());
        $result = $login->completeSecondFactor($this->code($secret), remember: true);
        $this->assertNotNull($result->deviceToken);

        [$again] = $this->login($twoFactor);
        $this->assertTrue($again->start('ada@example.com', 'secret-pass', deviceToken: $result->deviceToken)->signedIn(), 'a remembered device');
        $this->assertTrue($again->start('ada@example.com', 'secret-pass', deviceToken: 'forged')->needsSecondFactor());

        $twoFactor->disable($user);
        $twoFactor->confirm($user, $this->code($twoFactor->enrol($user)->secret));
        [$third] = $this->login($twoFactor);
        $this->assertTrue($third->start('ada@example.com', 'secret-pass', deviceToken: $result->deviceToken)->needsSecondFactor(), 'enrolling again forgets remembered devices');
    }

    public function testUsersWithoutASecondFactorSignInWithTheirPassword(): void
    {
        [$login] = $this->login($this->twoFactor());

        $this->assertTrue($login->start('ada@example.com', 'secret-pass')->signedIn());
        $this->assertFalse($login->hasPendingSecondFactor());
    }

    public function testOneTimeCodesExpireWorkOnceAndLimitAttempts(): void
    {
        $codes = new OneTimeCodes($this->cache, str_repeat('k', 32), new RateLimiter($this->cache, fn (): int => $this->now), maxIssues: 3, clock: fn (): int => $this->now);

        $code = $codes->issue('+243810000000', 'phone.confirm');
        $this->assertMatchesRegularExpression('/^\d{6}$/', $code);
        $this->assertFalse($codes->verify('+243810000000', 'phone.change', $code), 'another purpose');
        $this->assertTrue($codes->verify('+243810000000', 'phone.confirm', $code));
        $this->assertFalse($codes->verify('+243810000000', 'phone.confirm', $code), 'once');

        $code = $codes->issue('+243810000000', 'phone.confirm', ttl: 600);
        $this->now += 601;
        $this->assertFalse($codes->verify('+243810000000', 'phone.confirm', $code), 'expired');

        $code = $codes->issue('+243810000000', 'phone.confirm', maxAttempts: 2);
        $wrong = $code === '000000' ? '000001' : '000000';
        $this->assertFalse($codes->verify('+243810000000', 'phone.confirm', $wrong));
        $this->assertFalse($codes->verify('+243810000000', 'phone.confirm', $wrong));
        $this->assertFalse($codes->verify('+243810000000', 'phone.confirm', $code), 'out of attempts');

        $this->expectException(TooManyRequestsHttpException::class);
        $codes->issue('+243810000000', 'phone.confirm');   // the fourth this hour
    }

    private function twoFactor(int $maxAttempts = 5, string $key = 'kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk'): TwoFactor
    {
        return new TwoFactor(
            $this->users,
            $key,
            new TokenSigner(str_repeat('s', 32), fn (): int => $this->now),
            new Totp(fn (): int => $this->now),
            new RateLimiter($this->cache, fn (): int => $this->now),
            new EventDispatcher((new ListenerProvider())->listen(SecurityEvent::class, function (SecurityEvent $e): void {
                $this->events[] = $e;
            })),
            maxAttempts: $maxAttempts,
        );
    }

    /**
     * @return array{SessionLogin, Session, SecurityContext}
     */
    private function login(TwoFactor $twoFactor): array
    {
        $session = new Session();
        $context = new SecurityContext();
        $events = new EventDispatcher((new ListenerProvider())->listen(SecurityEvent::class, function (SecurityEvent $e): void {
            $this->events[] = $e;
        }));

        return [new SessionLogin($this->users, new PasswordHasher(['cost' => 4], PASSWORD_BCRYPT), $session, $context, events: $events, twoFactor: $twoFactor, clock: fn (): int => $this->now), $session, $context];
    }

    private static function signedInId(SecurityContext $context): ?string
    {
        return $context->user()?->identifier();
    }

    private function code(string $secret): string
    {
        return (new Totp(fn (): int => $this->now))->code($secret);
    }
}
