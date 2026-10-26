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
use Zana\Security\Middleware\RateLimitMiddleware;
use Zana\Security\RateLimit\RateLimiter;
use Zana\Security\Session\SessionAuthenticationMiddleware;
use Zana\Security\Session\SessionLogin;
use Zana\Session\SessionContext;
use Zana\Session\SessionInterface;

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
            })->uses(ConfigurationInterface::class)
            ->singleton(TokenSigner::class, static function (ServiceResolverInterface $r): TokenSigner {
                $config = $r->get(ConfigurationInterface::class);
                if (!$config->has('security.secret')) {
                    throw new SecurityException('Set security.secret (at least ' . TokenSigner::MIN_SECRET_LENGTH . ' bytes, e.g. from the environment) to issue or verify tokens.');
                }

                return new TokenSigner($config->string('security.secret'));
            })->uses(ConfigurationInterface::class)
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
            })->uses(ConfigurationInterface::class)
            ->scoped(SecurityContext::class)
            ->scoped(AuthenticationMiddleware::class, static fn (ServiceResolverInterface $r): AuthenticationMiddleware => new AuthenticationMiddleware(
                $r->get(TokenSigner::class),
                $r->get(UserProviderInterface::class),
                $r->get(SecurityContext::class),
            ))->uses(TokenSigner::class, UserProviderInterface::class, SecurityContext::class)
            ->scoped(AuthorizationMiddleware::class, static fn (ServiceResolverInterface $r): AuthorizationMiddleware => new AuthorizationMiddleware(
                $r->get(SecurityContext::class),
                $r->get(Authorizer::class),
            ))->uses(SecurityContext::class, Authorizer::class)
            ->singleton(CsrfTokens::class, static function (ServiceResolverInterface $r): CsrfTokens {
                $config = $r->get(ConfigurationInterface::class);
                $cache = $r->has(CacheInterface::class) ? $r->get(CacheInterface::class) : null;

                return new CsrfTokens(
                    $r->get(TokenSigner::class),
                    $cache instanceof CacheInterface ? $cache : null,
                    $config->int('security.csrf.lifetime', 7200),
                    $config->bool('security.csrf.single_use', false),
                    $config->int('security.csrf.minimum_age', 0),
                    $config->has('security.csrf.honeypot') ? $config->string('security.csrf.honeypot') : null,
                );
            })->uses(ConfigurationInterface::class, CacheInterface::class, TokenSigner::class)
            ->scoped(CsrfMiddleware::class, static function (ServiceResolverInterface $r): CsrfMiddleware {
                $config = $r->get(ConfigurationInterface::class);
                $tokens = $r->get(CsrfTokens::class);
                assert($tokens instanceof CsrfTokens);

                return new CsrfMiddleware($tokens, $config->has('security.csrf.spam_redirect') ? $config->string('security.csrf.spam_redirect') : null);
            })->uses(ConfigurationInterface::class, CsrfTokens::class)
            ->singleton(RateLimiter::class, static fn (ServiceResolverInterface $r): RateLimiter => new RateLimiter(self::cache($r, 'Rate limiting')))->uses(CacheInterface::class)
            ->scoped(RateLimitMiddleware::class, static function (ServiceResolverInterface $r): RateLimitMiddleware {
                $limiter = $r->get(RateLimiter::class);
                $context = $r->get(SecurityContext::class);
                assert($limiter instanceof RateLimiter && $context instanceof SecurityContext);

                return new RateLimitMiddleware($limiter, $context);
            })->uses(RateLimiter::class, SecurityContext::class)
            // Scoped, so the user provider may be scoped like other repositories (FE-40)
            ->scoped(PasswordResetTokens::class, static function (ServiceResolverInterface $r): PasswordResetTokens {
                $signer = $r->get(TokenSigner::class);
                $users = $r->get(PasswordUserProviderInterface::class);
                assert($signer instanceof TokenSigner && $users instanceof PasswordUserProviderInterface);

                return new PasswordResetTokens($signer, self::cache($r, 'Password reset tokens'), $users, $r->get(ConfigurationInterface::class)->int('security.password_reset.lifetime', 3600));
            })->uses(TokenSigner::class, CacheInterface::class, PasswordUserProviderInterface::class, ConfigurationInterface::class);

        if (interface_exists(SessionInterface::class)) {
            $services
                ->scoped(SessionLogin::class, static function (ServiceResolverInterface $r): SessionLogin {
                    $config = $r->get(ConfigurationInterface::class);
                    $users = $r->get(PasswordUserProviderInterface::class);
                    $hasher = $r->get(PasswordHasher::class);
                    $session = $r->get(SessionInterface::class);
                    $context = $r->get(SecurityContext::class);
                    $limiter = $r->has(CacheInterface::class) ? $r->get(RateLimiter::class) : null;
                    assert($users instanceof PasswordUserProviderInterface && $hasher instanceof PasswordHasher && $session instanceof SessionInterface && $context instanceof SecurityContext);

                    return new SessionLogin($users, $hasher, $session, $context, $limiter instanceof RateLimiter ? $limiter : null, $config->int('security.login.max_attempts', 5), $config->int('security.login.window', 900));
                })->uses(ConfigurationInterface::class, PasswordUserProviderInterface::class, PasswordHasher::class, SessionInterface::class, SecurityContext::class, RateLimiter::class)
                ->scoped(SessionAuthenticationMiddleware::class, static function (ServiceResolverInterface $r): SessionAuthenticationMiddleware {
                    $config = $r->get(ConfigurationInterface::class);
                    $sessions = $r->get(SessionContext::class);
                    $users = $r->has(UserProviderInterface::class) ? $r->get(UserProviderInterface::class) : $r->get(PasswordUserProviderInterface::class);
                    $context = $r->get(SecurityContext::class);
                    assert($sessions instanceof SessionContext && $users instanceof UserProviderInterface && $context instanceof SecurityContext);

                    return new SessionAuthenticationMiddleware($sessions, $users, $context, $config->has('security.login.path') ? $config->string('security.login.path') : null);
                })->uses(ConfigurationInterface::class, SessionContext::class, UserProviderInterface::class, PasswordUserProviderInterface::class, SecurityContext::class);
        }
    }

    private static function cache(ServiceResolverInterface $resolver, string $feature): CacheInterface
    {
        if (!$resolver->has(CacheInterface::class)) {
            throw new SecurityException("{$feature} need a PSR-16 cache: register mj-zana/cache or another " . CacheInterface::class . '.');
        }
        $cache = $resolver->get(CacheInterface::class);
        assert($cache instanceof CacheInterface);

        return $cache;
    }

    public function origin(): string
    {
        return 'package:mj-zana/security';
    }
}
