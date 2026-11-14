<?php

declare(strict_types=1);

namespace Zana\Security\Inspection;

use Psr\SimpleCache\CacheInterface;
use Zana\Configuration\ConfigurationInterface;
use Zana\Core\ApplicationInterface;
use Zana\Core\Inspection\ApplicationCheck;
use Zana\Core\Inspection\Finding;
use Zana\Core\Inspection\SecurityRules;
use Zana\Core\Inspection\Severity;
use Zana\Routing\Router;
use Zana\Security\Attribute\SpamRules;
use Zana\Security\Internal\HandlerReflection;
use Zana\Security\Middleware\SpamGuardMiddleware;
use Zana\Security\Spam\SpamGuard;

/**
 * security.spam_rules (2.24, FE-63): spam rules that would refuse nothing.
 * Errors with security.strict, warnings otherwise, except where noted:
 *
 * - a form's settings that cannot be used (an unknown setting, a wrong
 *   value, a rule class that is not a rule, a redirect off the site, no rule
 *   at all, duplicate_minutes without a PSR-16 cache);
 * - #[SpamRules('form')] on a handler with no SpamGuardMiddleware on its
 *   route, so nothing enforces it;
 * - #[SpamRules('form')] naming a form without settings;
 * - always a warning: #[SpamRules] on a route that receives no POST, PUT or
 *   PATCH, which the rules never read.
 */
final readonly class SpamRulesCheck implements ApplicationCheck
{
    public function findings(ApplicationInterface $application): array
    {
        $container = $application->container();
        $config = $container->get(ConfigurationInterface::class);
        assert($config instanceof ConfigurationInterface);
        $strict = SecurityRules::severity($application);
        $forms = $config->array('security.spam.forms', []);
        $findings = [];

        foreach (SpamGuard::problems($forms, $container->has(CacheInterface::class)) as $problem) {
            $findings[] = new Finding('security.spam_rules', $strict, $problem, hint: 'See the settings in the security guide, "Spam rules".', security: true);
        }

        if (!class_exists(Router::class) || !$container->has(Router::class)) {
            return $findings;
        }
        $router = $container->get(Router::class);
        assert($router instanceof Router);
        foreach ($router->routes() as $route) {
            $rules = HandlerReflection::firstAttribute($route->handler, SpamRules::class);
            if ($rules === null) {
                continue;
            }
            $where = implode('|', $route->methods) . ' ' . $route->path;
            $file = HandlerReflection::location($route->handler);
            if (!RouteAccess::has($route->getMiddleware(), SpamGuardMiddleware::class)) {
                $findings[] = new Finding(
                    'security.spam_rules',
                    $strict,
                    "{$where} has #[SpamRules('{$rules->form}')], but SpamGuardMiddleware is not on the route, so its rules refuse nothing.",
                    $file,
                    hint: 'Add SpamGuardMiddleware to the route or its group: middleware: [SpamGuardMiddleware::class] in #[Route].',
                    security: true,
                );
            }
            if (!array_key_exists($rules->form, $forms)) {
                $findings[] = new Finding(
                    'security.spam_rules',
                    $strict,
                    "{$where} has #[SpamRules('{$rules->form}')], but security.spam.forms has no \"{$rules->form}\": the form has no rules, and every post to it fails.",
                    $file,
                    hint: "Add security.spam.forms.{$rules->form} in config/security.php, e.g. ['max_links' => 2].",
                    security: true,
                );
            }
            if (array_intersect($route->methods, ['POST', 'PUT', 'PATCH']) === []) {
                $findings[] = new Finding(
                    'security.spam_rules',
                    Severity::Warning,
                    "{$where} has #[SpamRules('{$rules->form}')], but receives no POST, PUT or PATCH, which is all the rules read.",
                    $file,
                    hint: 'Put #[SpamRules] on the handler that receives the form.',
                    security: true,
                );
            }
        }

        return $findings;
    }
}
