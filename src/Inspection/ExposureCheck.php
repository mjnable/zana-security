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
 * reviewed baseline of what the application exposes, security/exposure.json.
 * It only compares: it never writes the file, so CI cannot approve a change.
 *
 * - A route that is new, or whose access changed since the baseline: an
 *   error with security.strict, a warning otherwise, until someone reviews it
 *   and records it with `security:exposure --update`.
 * - A route in the baseline that is gone: a warning, as it exposes nothing.
 * - No baseline yet: a warning, in strict mode too, so a project that
 *   upgrades fails nothing (ADR-003). The skeletons ship theirs.
 * - A baseline that is not one security:exposure writes (not such a list, a
 *   hand edit, a route named twice): an error with security.strict.
 */
final readonly class ExposureCheck implements ApplicationCheck
{
    private const string COMMAND = 'php bin/console security:exposure';

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
                "There is no reviewed baseline of who may reach each route ({$file}), so a new route, or one whose access changes, goes unnoticed.",
                hint: 'Run ' . self::COMMAND . ' to see who may reach each route, review it, then ' . self::COMMAND . " --init, and commit {$file}.",
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
                "{$file} is not a baseline of routes: {$e->getMessage()}.",
                $file,
                hint: "Restore it from Git. If it is lost, delete it, review every route with " . self::COMMAND . ', and record them with --init.',
                security: true,
            )];
        }

        $findings = [];
        if (!$recorded->asWritten) {
            $findings[] = new Finding(
                'security.exposure',
                $strict,
                "{$file} is not as security:exposure writes it: it was edited by hand, or a route is named twice. A baseline is only recorded by the command, after a review.",
                $file,
                hint: 'Restore it from Git, or review the routes with ' . self::COMMAND . ' and record them with --update.',
                security: true,
            );
        }
        foreach ($current->changesSince($recorded) as $change) {
            $route = $change['route'];
            $findings[] = match ($change['change']) {
                'new' => new Finding(
                    'security.exposure',
                    $strict,
                    "{$route} is new, and not in the reviewed baseline {$file}: " . Exposure::describe($change['after'] ?? []) . ' may reach it.',
                    $current->locations[$route] ?? null,
                    hint: 'Review who may reach it, then record it with ' . self::COMMAND . " --update, and commit {$file} with the route.",
                    security: true,
                ),
                'changed' => new Finding(
                    'security.exposure',
                    $strict,
                    "{$route}: who may reach it changed, from " . Exposure::describe($change['before'] ?? [])
                        . ' to ' . Exposure::describe($change['after'] ?? []) . ", and the reviewed baseline {$file} still records the former.",
                    $current->locations[$route] ?? null,
                    hint: 'Review the change, then record it with ' . self::COMMAND . " --update, and commit {$file} with it.",
                    security: true,
                ),
                'gone' => new Finding(
                    'security.exposure',
                    Severity::Warning,
                    "{$route} is in {$file}, but the application has no such route any more.",
                    $file,
                    hint: 'Remove it with ' . self::COMMAND . ' --update.',
                    security: true,
                ),
            };
        }

        return $findings;
    }
}
