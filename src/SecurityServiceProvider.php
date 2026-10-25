<?php

declare(strict_types=1);

namespace Zana\Security;

use Psr\SimpleCache\CacheInterface;
use Zana\Configuration\ConfigurationInterface;
use Zana\Container\Contracts\ServiceCollectionInterface;
use Zana\Container\Contracts\ServiceResolverInterface;
use Zana\Core\ServiceProvider;
use Zana\Security\Middleware\AuthenticationMiddleware;
use Zana\Security\Middleware\AuthorizationMiddleware;
use Zana\Security\Middleware\CsrfMiddleware;

/**
 * Registers the hasher, the token signer (secret from security.secret), the
 * authorizer (security.roles, security.hierarchy, security.policies), the
 * scoped SecurityContext, CSRF tokens (security.csrf.lifetime,
 * security.csrf.single_use, which needs a PSR-16 cache) and the middleware.
 *
 * Policies are resolved from the container when registered there, otherwise
 * created without arguments. AuthenticationMiddleware needs the application's
 * UserProviderInterface.
 */
final class SecurityServiceProvider extends ServiceProvider
{
    public function register(ServiceCollectionInterface $services): void
    {
        $services
            ->singleton(PasswordHasher::class, static function (ServiceResolverInterface $r): PasswordHasher {
                /** @var array<string, int> $options */
                $options = $r->get(ConfigurationInterface::class)->array('security.password_options', []);

                return new PasswordHasher($options);
            })
            ->singleton(TokenSigner::class, static function (ServiceResolverInterface $r): TokenSigner {
                $config = $r->get(ConfigurationInterface::class);
                if (!$config->has('security.secret')) {
                    throw new SecurityException('Set security.secret (at least ' . TokenSigner::MIN_SECRET_LENGTH . ' bytes, e.g. from the environment) to issue or verify tokens.');
                }

                return new TokenSigner($config->string('security.secret'));
            })
            ->singleton(Authorizer::class, static function (ServiceResolverInterface $r): Authorizer {
                $config = $r->get(ConfigurationInterface::class);
                /** @var array<string, list<string>> $roles */
                $roles = $config->array('security.roles', []);
                /** @var array<string, list<string>> $hierarchy */
                $hierarchy = $config->array('security.hierarchy', []);

                $policies = [];
                foreach ($config->array('security.policies', []) as $class) {
                    if (!is_string($class) || !is_a($class, PolicyInterface::class, true)) {
                        throw new SecurityException('security.policies must list classes implementing ' . PolicyInterface::class . '; got ' . get_debug_type($class) . '.');
                    }
                    $policies[] = $r->has($class) ? $r->get($class) : new $class();
                }

                return new Authorizer($roles, $hierarchy, $policies);
            })
            ->scoped(SecurityContext::class)
            ->scoped(AuthenticationMiddleware::class, static fn (ServiceResolverInterface $r): AuthenticationMiddleware => new AuthenticationMiddleware(
                $r->get(TokenSigner::class),
                $r->get(UserProviderInterface::class),
                $r->get(SecurityContext::class),
            ))
            ->scoped(AuthorizationMiddleware::class, static fn (ServiceResolverInterface $r): AuthorizationMiddleware => new AuthorizationMiddleware(
                $r->get(SecurityContext::class),
                $r->get(Authorizer::class),
            ))
            ->singleton(CsrfTokens::class, static function (ServiceResolverInterface $r): CsrfTokens {
                $config = $r->get(ConfigurationInterface::class);
                $cache = $r->has(CacheInterface::class) ? $r->get(CacheInterface::class) : null;

                return new CsrfTokens(
                    $r->get(TokenSigner::class),
                    $cache instanceof CacheInterface ? $cache : null,
                    $config->int('security.csrf.lifetime', 7200),
                    $config->bool('security.csrf.single_use', false),
                );
            })
            ->scoped(CsrfMiddleware::class);
    }

    public function origin(): string
    {
        return 'package:mj-zana/security';
    }
}
