<?php

declare(strict_types=1);

namespace Zana\Security\Tests;

use PHPUnit\Framework\TestCase;
use Zana\Security\TokenSigner;
use Zana\Security\TwoFactor\Totp;
use Zana\Security\TwoFactor\TwoFactor;
use Zana\Security\TwoFactorStateSwapInterface;
use Zana\Security\UserInterface;

/**
 * Two sign-ins at the same moment (2.20, S14). The provider below lets a
 * test hand one request the state as it was before the other one wrote,
 * which is what a slower parallel request sees.
 */
final class TwoFactorRaceTest extends TestCase
{
    private int $now = 1_800_000_000;

    public function testAUsedRecoveryCodeDoesNotComeBack(): void
    {
        $users = new SwappingUsers();
        $twoFactor = $this->twoFactor($users);
        $user = new BackOfficeUser();
        $enrolment = $twoFactor->enrol($user);
        $twoFactor->confirm($user, $this->code($enrolment->secret));
        $before = $users->state;

        $this->assertTrue($twoFactor->verify($user, $enrolment->recoveryCodes[0]), 'request A uses code 1');
        $users->staleRead = $before;   // request B read the state before A saved it
        $this->assertFalse($twoFactor->verify($user, $enrolment->recoveryCodes[1]), 'B is refused: the state changed under it');
        $users->staleRead = null;

        $this->assertFalse($twoFactor->verify($user, $enrolment->recoveryCodes[0]), 'code 1 stays used');
        $this->assertTrue($twoFactor->verify($user, $enrolment->recoveryCodes[1]), 'B tries again, and its code works');
        $this->assertSame(8, $twoFactor->remainingRecoveryCodes($user));
    }

    public function testATotpCodeCountsOnceAcrossParallelSignIns(): void
    {
        $users = new SwappingUsers();
        $twoFactor = $this->twoFactor($users);
        $user = new BackOfficeUser();
        $secret = $twoFactor->enrol($user)->secret;
        $twoFactor->confirm($user, $this->code($secret));
        $this->now += 30;
        $before = $users->state;

        $code = $this->code($secret);
        $this->assertTrue($twoFactor->verify($user, $code));
        $users->staleRead = $before;   // a second request with the same code, which read the old state
        $this->assertFalse($twoFactor->verify($user, $code), 'one code, one sign-in');
    }

    private function twoFactor(SwappingUsers $users): TwoFactor
    {
        $clock = fn (): int => $this->now;

        return new TwoFactor($users, str_repeat('k', 40), new TokenSigner(str_repeat('s', 40), $clock), new Totp($clock));
    }

    private function code(string $secret): string
    {
        return (new Totp(fn (): int => $this->now))->code($secret);
    }
}

final class SwappingUsers implements TwoFactorStateSwapInterface
{
    public ?string $state = null;

    /** What the next read returns instead of the stored state: a request that read earlier. */
    public ?string $staleRead = null;

    public function findByIdentifier(string $identifier): ?UserInterface
    {
        return $identifier === '1' ? new BackOfficeUser() : null;
    }

    public function twoFactorStateFor(UserInterface $user): ?string
    {
        return $this->staleRead ?? $this->state;
    }

    public function saveTwoFactorState(UserInterface $user, ?string $state): void
    {
        $this->state = $state;
    }

    public function swapTwoFactorState(UserInterface $user, ?string $expected, ?string $new): bool
    {
        if ($this->state !== $expected) {
            return false;
        }
        $this->state = $new;

        return true;
    }
}
