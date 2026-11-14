<?php

declare(strict_types=1);

namespace Zana\Security;

use Psr\EventDispatcher\EventDispatcherInterface;
use Psr\Log\LoggerInterface;
use Psr\SimpleCache\CacheInterface;
use Zana\Configuration\ConfigurationInterface;
use Zana\Console\ConsoleKernel;
use Zana\Container\Contracts\ServiceCollectionInterface;
use Zana\Container\Contracts\ServiceResolverInterface;
use Zana\Core\ServiceProvider;
use Zana\Core\Inspection\ApplicationCheck;
use Zana\Database\ConnectionInterface;
use Zana\Security\Console\ExposureCommand;
use Zana\Security\Inspection\ExposureCheck;
use Zana\Security\Inspection\RoleAssignmentsCheck;
use Zana\Security\Inspection\SpamRulesCheck;
use Zana\Security\Middleware\SpamGuardMiddleware;
use Zana\Security\Spam\SpamGuard;
use Zana\Security\Spam\SpamRuleInterface;
use Zana\Security\Inspection\RouteAccessCheck;
use Zana\Security\Inspection\TwoFactorCheck;
use Zana\Security\Internal\MissingCache;
use Zana\Security\Middleware\AuthenticationMiddleware;
use Zana\Security\Middleware\AuthorizationMiddleware;
use Zana\Security\Middleware\CsrfMiddleware;
use Zana\Security\Middleware\RateLimitMiddleware;
use Zana\Security\RateLimit\RateLimiter;
use Zana\Security\Session\SessionAuthenticationMiddleware;
use Zana\Security\RoleAssignment\DatabaseRoleAssignmentStore;
use Zana\Security\RoleAssignment\RoleAssignments;
use Zana\Security\RoleAssignment\RoleAssignmentStoreInterface;
use Zana\Security\RoleAssignment\ScopeHierarchyInterface;
use Zana\Security\Session\SessionLogin;
use Zana\Security\TwoFactor\OneTimeCodes;
use Zana\Security\TwoFactor\Totp;
use Zana\Security\TwoFactor\TwoFactor;
use Zana\Session\SessionContext;
use Zana\Session\SessionInterface;

/**
 * Registers the hasher, the token signer (secret from security.secret), the
 * authorizer (security.roles, security.hierarchy, security.policies), the
 * scoped SecurityContext, CSRF tokens (security.csrf.lifetime,
 * security.csrf.single_use, which needs a PSR-16 cache) and the middleware.
 *
 * Second factors (2.16): TwoFactor (scoped; the user provider implements
 * TwoFactorUserProviderInterface; security.two_factor.key, .issuer,
 * .max_attempts, .window, .remember_days), OneTimeCodes
 * (security.one_time_codes.max_issues, .window) and the
 * security.two_factor_key check.
 *
 * Scoped roles (2.17): the role assignment store is the application's
 * RoleAssignmentStoreInterface, or DatabaseRoleAssignmentStore when
 * security.role_assignments is "database" (table
 * security.role_assignments_table); the Authorizer counts its roles, and a
 * registered ScopeHierarchyInterface gives scopes their parents.
 * RoleAssignments (scoped) changes them; the security.role_assignments
 * check reads the table.
 *
 * What is exposed (2.23, FE-68 layer 4): security:exposure, with
 * mj-zana/console, writes security/exposure.json, who may reach each route;
 * the security.exposure check reports a route that is new or whose access
 * changed since.
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

                $scopes = $r->has(ScopeHierarchyInterface::class) ? $r->get(ScopeHierarchyInterface::class) : null;

                return new Authorizer($roles, $hierarchy, $policies, self::assignmentStore($r), $scopes instanceof ScopeHierarchyInterface ? $scopes : null);
            })->uses(ConfigurationInterface::class, RoleAssignmentStoreInterface::class, ScopeHierarchyInterface::class, ConnectionInterface::class)
            ->scoped(RoleAssignments::class, static function (ServiceResolverInterface $r): RoleAssignments {
                $store = self::assignmentStore($r) ?? throw new SecurityException('Role assignments need a store: set security.role_assignments to "database" (with mj-zana/database), or register a ' . RoleAssignmentStoreInterface::class . '.');
                $context = $r->get(SecurityContext::class);
                assert($context instanceof SecurityContext);

                return new RoleAssignments($store, self::events($r), $context);
            })->uses(RoleAssignmentStoreInterface::class, ConnectionInterface::class, ConfigurationInterface::class, EventDispatcherInterface::class, SecurityContext::class)
            ->singleton(RoleAssignmentsCheck::class, static fn (ServiceResolverInterface $r): RoleAssignmentsCheck => new RoleAssignmentsCheck(static fn (): ?RoleAssignmentStoreInterface => self::assignmentStore($r)))
            ->uses(RoleAssignmentStoreInterface::class, ConnectionInterface::class, ConfigurationInterface::class)
            ->tag(ApplicationCheck::TAG, RoleAssignmentsCheck::class)
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
            // 2.24, FE-63: spam rules per form. Scoped, so an application's rule may use scoped services.
            ->scoped(SpamGuard::class, static function (ServiceResolverInterface $r): SpamGuard {
                $config = $r->get(ConfigurationInterface::class);
                $cache = $r->has(CacheInterface::class) ? $r->get(CacheInterface::class) : null;
                assert($config instanceof ConfigurationInterface);

                return new SpamGuard(
                    $config->array('security.spam.forms', []),
                    $cache instanceof CacheInterface ? $cache : null,
                    static function (string $class) use ($r): SpamRuleInterface {
                        $rule = $r->has($class) ? $r->get($class) : new $class();
                        assert($rule instanceof SpamRuleInterface);

                        return $rule;
                    },
                    logger: $r->has(LoggerInterface::class) && ($logger = $r->get(LoggerInterface::class)) instanceof LoggerInterface ? $logger : null,
                );
            })->uses(ConfigurationInterface::class, CacheInterface::class, LoggerInterface::class)
            ->scoped(SpamGuardMiddleware::class, static function (ServiceResolverInterface $r): SpamGuardMiddleware {
                $config = $r->get(ConfigurationInterface::class);
                $guard = $r->get(SpamGuard::class);
                $context = $r->get(SecurityContext::class);
                assert($config instanceof ConfigurationInterface && $guard instanceof SpamGuard && $context instanceof SecurityContext);

                return new SpamGuardMiddleware(
                    $guard,
                    $config->has('security.csrf.honeypot') ? $config->string('security.csrf.honeypot') : null,
                    $config->has('security.csrf.spam_redirect') ? $config->string('security.csrf.spam_redirect') : null,
                    $context,
                    self::events($r),
                );
            })->uses(ConfigurationInterface::class, SpamGuard::class, SecurityContext::class, EventDispatcherInterface::class)
            ->singleton(SpamRulesCheck::class)
            ->tag(ApplicationCheck::TAG, SpamRulesCheck::class)
            // Scoped, so the user provider may be scoped like other repositories (FE-40)
            ->scoped(PasswordResetTokens::class, static function (ServiceResolverInterface $r): PasswordResetTokens {
                $signer = $r->get(TokenSigner::class);
                $users = $r->get(PasswordUserProviderInterface::class);
                assert($signer instanceof TokenSigner && $users instanceof PasswordUserProviderInterface);

                return new PasswordResetTokens($signer, self::cache($r, 'Password reset tokens'), $users, $r->get(ConfigurationInterface::class)->int('security.password_reset.lifetime', 3600), self::events($r));
            })->uses(TokenSigner::class, CacheInterface::class, PasswordUserProviderInterface::class, ConfigurationInterface::class, EventDispatcherInterface::class)
            // Scoped, as the user provider may be (FE-40)
            ->scoped(TwoFactor::class, static function (ServiceResolverInterface $r): TwoFactor {
                $config = $r->get(ConfigurationInterface::class);
                $users = $r->has(PasswordUserProviderInterface::class) ? $r->get(PasswordUserProviderInterface::class) : null;
                if (!$users instanceof TwoFactorUserProviderInterface) {
                    throw new SecurityException('Second factors need a user provider (PasswordUserProviderInterface) that implements ' . TwoFactorUserProviderInterface::class . '.');
                }
                $signer = $r->get(TokenSigner::class);
                $limiter = $r->has(CacheInterface::class) ? $r->get(RateLimiter::class) : null;
                assert($config instanceof ConfigurationInterface && $signer instanceof TokenSigner);

                return new TwoFactor(
                    $users,
                    $config->has('security.two_factor.key') ? $config->string('security.two_factor.key') : '',
                    $signer,
                    new Totp(),
                    $limiter instanceof RateLimiter ? $limiter : null,
                    self::events($r),
                    $config->string('security.two_factor.issuer', $config->string('app.name', 'Zana')),
                    $config->int('security.two_factor.max_attempts', 5),
                    $config->int('security.two_factor.window', 900),
                    $config->int('security.two_factor.remember_days', 30),
                );
            })->uses(ConfigurationInterface::class, PasswordUserProviderInterface::class, TokenSigner::class, RateLimiter::class, EventDispatcherInterface::class)
            ->singleton(OneTimeCodes::class, static function (ServiceResolverInterface $r): OneTimeCodes {
                $config = $r->get(ConfigurationInterface::class);
                $limiter = $r->has(CacheInterface::class) ? $r->get(RateLimiter::class) : null;
                assert($config instanceof ConfigurationInterface);
                // Codes live minutes: security.secret may key them when there is no two-factor key.
                $key = $config->has('security.two_factor.key') ? $config->string('security.two_factor.key') : ($config->has('security.secret') ? $config->string('security.secret') : '');

                return new OneTimeCodes(
                    self::cache($r, 'One-time codes'),
                    $key,
                    $limiter instanceof RateLimiter ? $limiter : null,
                    $config->int('security.one_time_codes.max_issues', 5),
                    $config->int('security.one_time_codes.window', 3600),
                );
            })->uses(ConfigurationInterface::class, CacheInterface::class, RateLimiter::class)
            ->singleton(TwoFactorCheck::class)
            ->tag(ApplicationCheck::TAG, TwoFactorCheck::class)
            // 2.21, FE-68: who may reach each route. It reads the router only when mj-zana/routing is installed.
            ->singleton(RouteAccessCheck::class)
            ->tag(ApplicationCheck::TAG, RouteAccessCheck::class)
            // 2.23, FE-68 layer 4: the routes against the reviewed list, security/exposure.json.
            ->singleton(ExposureCheck::class)
            ->tag(ApplicationCheck::TAG, ExposureCheck::class);

        if (class_exists(ConsoleKernel::class)) {
            $services->singleton(ExposureCommand::class)->tag(ConsoleKernel::TAG, ExposureCommand::class);
        }

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

                    // A user provider that can hold second factors gets them checked: a password alone never signs such a user in.
                    $twoFactor = $users instanceof TwoFactorUserProviderInterface ? $r->get(TwoFactor::class) : null;

                    return new SessionLogin($users, $hasher, $session, $context, $limiter instanceof RateLimiter ? $limiter : null, $config->int('security.login.max_attempts', 5), $config->int('security.login.window', 900), self::events($r), $twoFactor instanceof TwoFactor ? $twoFactor : null);
                })->uses(ConfigurationInterface::class, PasswordUserProviderInterface::class, PasswordHasher::class, SessionInterface::class, SecurityContext::class, RateLimiter::class, EventDispatcherInterface::class, TwoFactor::class)
                ->scoped(SessionAuthenticationMiddleware::class, static function (ServiceResolverInterface $r): SessionAuthenticationMiddleware {
                    $config = $r->get(ConfigurationInterface::class);
                    $sessions = $r->get(SessionContext::class);
                    $users = $r->has(UserProviderInterface::class) ? $r->get(UserProviderInterface::class) : $r->get(PasswordUserProviderInterface::class);
                    $context = $r->get(SecurityContext::class);
                    assert($sessions instanceof SessionContext && $users instanceof UserProviderInterface && $context instanceof SecurityContext);

                    $passwords = $r->has(PasswordUserProviderInterface::class) ? $r->get(PasswordUserProviderInterface::class) : null;

                    return new SessionAuthenticationMiddleware($sessions, $users, $context, $config->has('security.login.path') ? $config->string('security.login.path') : null, $passwords instanceof PasswordUserProviderInterface ? $passwords : null);
                })->uses(ConfigurationInterface::class, SessionContext::class, UserProviderInterface::class, PasswordUserProviderInterface::class, SecurityContext::class);
        }
    }

    /**
     * The application's cache; without one, a stand-in that fails when used, not when the service is created (2.9).
     */
    private static function cache(ServiceResolverInterface $resolver, string $feature): CacheInterface
    {
        if (!$resolver->has(CacheInterface::class)) {
            return new MissingCache($feature);
        }
        $cache = $resolver->get(CacheInterface::class);
        assert($cache instanceof CacheInterface);

        return $cache;
    }

    /**
     * The application's RoleAssignmentStoreInterface, else the database store when
     * security.role_assignments is "database", else none (2.17).
     */
    private static function assignmentStore(ServiceResolverInterface $resolver): ?RoleAssignmentStoreInterface
    {
        if ($resolver->has(RoleAssignmentStoreInterface::class)) {
            $store = $resolver->get(RoleAssignmentStoreInterface::class);
            assert($store instanceof RoleAssignmentStoreInterface);

            return $store;
        }
        $config = $resolver->get(ConfigurationInterface::class);
        assert($config instanceof ConfigurationInterface);
        if (!$config->has('security.role_assignments')) {
            return null;
        }
        if ($config->string('security.role_assignments') !== 'database' || !interface_exists(ConnectionInterface::class)) {
            throw new SecurityException('security.role_assignments must be "database" (with mj-zana/database); or register a ' . RoleAssignmentStoreInterface::class . '.');
        }
        $connection = $resolver->get(ConnectionInterface::class);
        assert($connection instanceof ConnectionInterface);

        return new DatabaseRoleAssignmentStore($connection, $config->string('security.role_assignments_table', DatabaseRoleAssignmentStore::TABLE));
    }

    /**
     * The application's event dispatcher, when mj-zana/events (or another PSR-14 dispatcher) is registered (2.15).
     */
    private static function events(ServiceResolverInterface $resolver): ?EventDispatcherInterface
    {
        $events = $resolver->has(EventDispatcherInterface::class) ? $resolver->get(EventDispatcherInterface::class) : null;

        return $events instanceof EventDispatcherInterface ? $events : null;
    }

    public function origin(): string
    {
        return 'package:mj-zana/security';
    }
}
