<?php

declare(strict_types=1);

namespace Zana\Security\Inspection;

use Psr\SimpleCache\CacheInterface;
use Zana\Cache\AtomicCacheInterface;
use Zana\Configuration\ConfigurationInterface;
use Zana\Core\ApplicationInterface;
use Zana\Core\Inspection\ApplicationCheck;
use Zana\Core\Inspection\Finding;
use Zana\Core\Inspection\Severity;
use Zana\Routing\Router;
use Zana\Security\Attribute\RateLimit;
use Zana\Security\Internal\HandlerReflection;
use Zana\Security\Session\SessionLogin;

/**
 * security.atomic_cache (2.26, S34, S35), always a warning: the PSR-16 cache
 * cannot add or count atomically, and something relies on it, so requests
 * at the same instant can all pass where one should: a rate limit
 * (#[RateLimit], sign-in attempts), a single-use CSRF token, the spam rules'
 * repeat detection. Every Zana store can; a cache from elsewhere may not.
 */
final readonly class AtomicCacheCheck implements ApplicationCheck
{
    public function findings(ApplicationInterface $application): array
    {
        $container = $application->container();
        if (!$container->has(CacheInterface::class)) {
            return [];
        }
        $cache = $container->get(CacheInterface::class);
        if ($cache instanceof AtomicCacheInterface) {
            return [];
        }
        $config = $container->get(ConfigurationInterface::class);
        assert($config instanceof ConfigurationInterface);

        $uses = [];
        if (class_exists(Router::class) && $container->has(Router::class)) {
            $router = $container->get(Router::class);
            assert($router instanceof Router);
            foreach ($router->routes() as $route) {
                if (HandlerReflection::firstAttribute($route->handler, RateLimit::class) !== null) {
                    $uses[] = 'rate limits (#[RateLimit])';
                    break;
                }
            }
        }
        if ($container->has(SessionLogin::class)) {
            $uses[] = 'the limit on sign-in attempts';
        }
        if ($config->bool('security.csrf.single_use', false)) {
            $uses[] = 'single-use CSRF tokens';
        }
        foreach ($config->array('security.spam.forms', []) as $form) {
            if (is_array($form) && isset($form['duplicate_minutes'])) {
                $uses[] = 'the spam rules\' repeat detection';
                break;
            }
        }
        if ($uses === []) {
            return [];
        }

        return [new Finding(
            'security.atomic_cache',
            Severity::Warning,
            'The cache (' . (is_object($cache) ? $cache::class : 'unknown') . ') cannot add or count atomically, so requests at the same instant can all pass '
                . implode(', ', $uses) . ': twenty at once passed a limit of five.',
            hint: 'Use a mj-zana/cache store (cache.default: file or array), whose add() and increment() are atomic, or a cache implementing '
                . 'Zana\Cache\AtomicCacheInterface, e.g. on Redis INCR and SET NX.',
            security: true,
        )];
    }
}
