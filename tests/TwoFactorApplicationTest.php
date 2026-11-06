<?php

declare(strict_types=1);

namespace Zana\Security\Tests;

use PHPUnit\Framework\TestCase;
use Psr\SimpleCache\CacheInterface;
use Zana\Container\Contracts\ServiceCollectionInterface;
use Zana\Core\Application;
use Zana\Core\ApplicationInterface;
use Zana\Core\Inspection\ApplicationCheck;
use Zana\Core\Inspection\Finding;
use Zana\Http\HttpServiceProvider;
use Zana\Security\Inspection\TwoFactorCheck;
use Zana\Security\PasswordHasher;
use Zana\Security\PasswordUserProviderInterface;
use Zana\Security\SecurityException;
use Zana\Security\SecurityServiceProvider;
use Zana\Security\TwoFactor\OneTimeCodes;
use Zana\Security\TwoFactor\TwoFactor;

/**
 * The provider's second factors (ADR-031): TwoFactor needs a user provider
 * that holds them and security.two_factor.key, which check reports;
 * OneTimeCodes work with security.secret alone.
 */
final class TwoFactorApplicationTest extends TestCase
{
    public function testTheKeyIsCheckedWhenTheUserProviderHoldsSecondFactors(): void
    {
        $app = $this->app([]);
        $this->assertSame(['security.two_factor_key'], $this->findings($app));

        $scope = $app->container()->createScope();
        try {
            $scope->get(TwoFactor::class);
            $this->fail('Without its key, the second factor fails rather than let a password alone in.');
        } catch (\Throwable $e) {
            $cause = $e;
            while (!$cause instanceof SecurityException && $cause->getPrevious() !== null) {
                $cause = $cause->getPrevious();
            }
            $this->assertInstanceOf(SecurityException::class, $cause, 'the container wraps it');
            $this->assertStringContainsString('security.two_factor.key', $cause->getMessage());
        } finally {
            $scope->dispose();
        }

        $this->assertSame(['security.two_factor_key'], $this->findings($this->app(['security.two_factor.key' => 'too-short'])));

        $ready = $this->app(['security.two_factor.key' => str_repeat('k', 64), 'app.name' => 'Billets RDC']);
        $this->assertSame([], $this->findings($ready));
        $scope = $ready->container()->createScope();
        $twoFactor = $scope->get(TwoFactor::class);
        assert($twoFactor instanceof TwoFactor);
        $this->assertStringStartsWith('otpauth://totp/Billets%20RDC:', $twoFactor->enrol(new BackOfficeUser())->uri, 'the issuer is app.name');
        $scope->dispose();
    }

    public function testApplicationsWithoutSecondFactorsAreNotAskedForAKey(): void
    {
        $app = Application::configure(sys_get_temp_dir() . '/zana-security-2fa')->withEnvironment('testing')
            ->withConfiguration(['security.secret' => str_repeat('s', 32)])
            ->withProviders(HttpServiceProvider::class, SecurityServiceProvider::class)
            ->withServices(static fn (ServiceCollectionInterface $s) => $s
                ->instance(PasswordUserProviderInterface::class, new LoginUsers('x'))
                ->instance(CacheInterface::class, new ArrayCache()))
            ->build();

        $this->assertSame([], $this->findings($app));
        $codes = $app->container()->get(OneTimeCodes::class);
        assert($codes instanceof OneTimeCodes);
        $this->assertTrue($codes->verify('a@example.com', 'email.confirm', $codes->issue('a@example.com', 'email.confirm')), 'keyed by security.secret');
    }

    /**
     * @param array<string, mixed> $config
     */
    private function app(array $config): ApplicationInterface
    {
        $users = new TwoFactorUsers((new PasswordHasher(['cost' => 4], PASSWORD_BCRYPT))->hash('secret-pass'));

        return Application::configure(sys_get_temp_dir() . '/zana-security-2fa')->withEnvironment('testing')
            ->withConfiguration(['security.secret' => str_repeat('s', 32), ...$config])
            ->withProviders(HttpServiceProvider::class, SecurityServiceProvider::class)
            ->withServices(static fn (ServiceCollectionInterface $s) => $s
                ->instance(PasswordUserProviderInterface::class, $users)
                ->instance(CacheInterface::class, new ArrayCache()))
            ->build();
    }

    /**
     * @return list<string>
     */
    private function findings(ApplicationInterface $app): array
    {
        foreach ($app->container()->tagged(ApplicationCheck::TAG) as $check) {
            if ($check instanceof TwoFactorCheck) {
                return array_map(static fn (Finding $f): string => $f->id, $check->findings($app));
            }
        }
        self::fail('TwoFactorCheck is not tagged.');
    }
}
