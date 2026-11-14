<?php

declare(strict_types=1);

namespace Zana\Security\Inspection;

use Zana\Configuration\ConfigurationInterface;
use Zana\Core\ApplicationInterface;
use Zana\Core\Inspection\ApplicationCheck;
use Zana\Core\Inspection\Finding;
use Zana\Core\Inspection\SecurityRules;
use Zana\Core\Inspection\Severity;
use Zana\Routing\Router;

/**
 * security.exposure (2.23, FE-68 layer 4, ADR-033): the routes against the
 * reviewed list of what the application exposes, security/exposure.json.
 *
 * - A route that is new, or whose access changed since the list was written:
 *   an error with security.strict, a warning otherwise, until someone reviews
 *   it and runs `php bin/console security:exposure`.
 * - A route in the list that is gone: a warning, as it exposes nothing.
 * - No list yet: a warning, in strict mode too, so a project that upgrades
 *   fails nothing (ADR-003). The skeletons ship theirs.
 * - A list that cannot be read: an error with security.strict.
 */
final readonly class ExposureCheck implements ApplicationCheck
{
    private const string WRITE = 'php bin/console security:exposure';

    public function findings(ApplicationInterface $application): array
    {
        $container = $application->container();
        if (!class_exists(Router::class) || !$container->has(Router::class)) {
            return [];
        }
        $router = $container->get(Router::class);
        $config = $container->get(ConfigurationInterface::class);
        assert($router instanceof Router && $config instanceof ConfigurationInterface);

        $current = Exposure::of($router, $config);
        if ($current->routes === []) {
            return [];
        }
        $file = Exposure::FILE;
        $path = $application->path(...explode('/', $file));
        if (!is_file($path)) {
            return [new Finding(
                'security.exposure',
                Severity::Warning,
                "There is no reviewed list of who may reach each route ({$file}), so a new route, or one whose access changes, goes unnoticed.",
                hint: 'Run ' . self::WRITE . ", review who may reach each route it lists, and commit {$file}. check then reports each change until the file is written again.",
                security: true,
            )];
        }

        $strict = SecurityRules::severity($application);
        try {
            $recorded = Exposure::read($path);
        } catch (\UnexpectedValueException $e) {
            return [new Finding(
                'security.exposure',
                $strict,
                "{$file} is not a list of routes: {$e->getMessage()}.",
                $file,
                hint: 'Run ' . self::WRITE . ' to write it again, and review the diff.',
                security: true,
            )];
        }

        $findings = [];
        foreach ($current->changesSince($recorded) as $change) {
            $route = $change['route'];
            $findings[] = match ($change['change']) {
                'new' => new Finding(
                    'security.exposure',
                    $strict,
                    "{$route} is new, and not yet in {$file}: " . Exposure::describe($change['after'] ?? []) . ' may reach it.',
                    $current->locations[$route] ?? null,
                    hint: 'Review who may reach it, then run ' . self::WRITE . " and commit {$file} with the route.",
                    security: true,
                ),
                'changed' => new Finding(
                    'security.exposure',
                    $strict,
                    "{$route}: who may reach it changed, from " . Exposure::describe($change['before'] ?? [])
                        . ' to ' . Exposure::describe($change['after'] ?? []) . ", and {$file} still records the former.",
                    $current->locations[$route] ?? null,
                    hint: 'Review the change, then run ' . self::WRITE . " and commit {$file} with it.",
                    security: true,
                ),
                'gone' => new Finding(
                    'security.exposure',
                    Severity::Warning,
                    "{$route} is in {$file}, but the application has no such route any more.",
                    $file,
                    hint: 'Run ' . self::WRITE . ' to remove it.',
                    security: true,
                ),
            };
        }

        return $findings;
    }
}
