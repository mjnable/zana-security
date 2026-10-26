<?php

declare(strict_types=1);

namespace Zana\Security\Tests;

use PHPUnit\Framework\TestCase;
use Psr\SimpleCache\CacheInterface;
use Zana\Container\Contracts\ContainerInterface;
use Zana\Container\Contracts\ServiceCollectionInterface;
use Zana\Container\Exception\ContainerBuildException;
use Zana\Core\Application;
use Zana\Security\PasswordResetTokens;
use Zana\Security\PasswordUserProviderInterface;
use Zana\Security\SecurityServiceProvider;

/**
 * FE-40: the user provider is an application repository, often scoped. Every
 * security service that uses it must work with a scoped one, and a mistake
 * must show when the container is built, not on a page few people open.
 */
final class UserProviderLifetimeTest extends TestCase
{
    public function testPasswordResetsWorkWithAScopedUserProvider(): void
    {
        $container = $this->container(static fn (ServiceCollectionInterface $s) => $s
            ->scoped(PasswordUserProviderInterface::class, static fn (): LoginUsers => new LoginUsers('hash-1')));

        $scope = $container->createScope();
        try {
            $resets = $scope->get(PasswordResetTokens::class);
            $users = $scope->get(PasswordUserProviderInterface::class);
            assert($resets instanceof PasswordResetTokens && $users instanceof PasswordUserProviderInterface);

            $token = $resets->issue($users->findByLogin('ada@example.com') ?? throw new \LogicException('No user.'));
            $this->assertSame('1', $resets->consume($token)?->identifier());
        } finally {
            $scope->dispose();
        }
    }

    public function testASingletonKeepingResetTokensFailsTheBuild(): void
    {
        try {
            $this->container(static fn (ServiceCollectionInterface $s) => $s
                ->scoped(PasswordUserProviderInterface::class, static fn (): LoginUsers => new LoginUsers('hash-1'))
                ->singleton(ResetMailer::class));
            $this->fail('The build should fail.');
        } catch (ContainerBuildException $e) {
            $this->assertStringContainsString(ResetMailer::class . ' (singleton, app) → ' . PasswordResetTokens::class . ' (scoped, package:mj-zana/security): a singleton must not depend on a scoped service', $e->getMessage());
        }
    }

    /**
     * @param \Closure(ServiceCollectionInterface): mixed $services
     */
    private function container(\Closure $services): ContainerInterface
    {
        return Application::configure(sys_get_temp_dir() . '/zana-security-lifetimes')
            ->withEnvironment('testing')
            ->withConfiguration(['security.secret' => str_repeat('s', 32)])
            ->withProviders(SecurityServiceProvider::class)
            ->withServices(static fn (ServiceCollectionInterface $s) => $s->instance(CacheInterface::class, new ArrayCache()))
            ->withServices($services)
            ->build()
            ->container();
    }
}

final class ResetMailer
{
    public function __construct(public readonly PasswordResetTokens $resets)
    {
    }
}
