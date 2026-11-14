<?php

declare(strict_types=1);

namespace Zana\Security\Console;

use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Style\SymfonyStyle;
use Zana\Configuration\ConfigurationInterface;
use Zana\Console\Command;
use Zana\Core\ApplicationInterface;
use Zana\Routing\Router;
use Zana\Security\Inspection\Exposure;

/**
 * security:exposure (2.23, FE-68 layer 4): writes security/exposure.json, who
 * may reach each route, and says what changed since it was last written.
 * Review that in the diff, then commit the file; `check` reports each change
 * until then.
 */
#[AsCommand(name: 'security:exposure', description: 'Write security/exposure.json, who may reach each route, for review')]
final class ExposureCommand extends Command
{
    public function handle(ApplicationInterface $application, SymfonyStyle $io): int
    {
        $container = $application->container();
        if (!class_exists(Router::class) || !$container->has(Router::class)) {
            $io->error('The application has no router (mj-zana/routing), so it has no routes to list.');

            return self::FAILURE;
        }
        $router = $container->get(Router::class);
        $config = $container->get(ConfigurationInterface::class);
        assert($router instanceof Router && $config instanceof ConfigurationInterface);

        $current = Exposure::of($router, $config);
        $file = Exposure::FILE;
        $path = $application->path(...explode('/', $file));
        $recorded = null;
        if (is_file($path)) {
            try {
                $recorded = Exposure::read($path);
            } catch (\UnexpectedValueException $e) {
                $io->warning("The current {$file} is not a list of routes ({$e->getMessage()}); it is written anew.");
            }
        }

        $contents = $current->encode();
        $changes = $recorded === null ? null : $current->changesSince($recorded);
        if ($changes === [] && @file_get_contents($path) === $contents) {
            $io->success("{$file} is up to date: " . count($current->routes) . ' route(s), nothing changed.');

            return self::SUCCESS;
        }
        if (!is_dir(dirname($path)) && !mkdir(dirname($path), 0o775, true) && !is_dir(dirname($path))) {
            $io->error("Cannot create the folder of {$file}.");

            return self::FAILURE;
        }
        if (file_put_contents($path, $contents) === false) {
            $io->error("Cannot write {$file}.");

            return self::FAILURE;
        }

        if ($changes === null) {
            $counts = array_count_values(array_map(static fn (array $entry): string => is_string($entry['access']) ? $entry['access'] : 'anyone', $current->routes));
            $io->writeln("Wrote {$file}: " . count($current->routes) . ' route(s), ' . self::counts($counts) . '.');
        } elseif ($changes === []) {
            $io->writeln("Wrote {$file}: nothing changed but its layout.");
        } else {
            $io->writeln("Wrote {$file}: " . count($changes) . ' change(s).');
            foreach ($changes as $change) {
                $io->writeln(match ($change['change']) {
                    'new' => "  + {$change['route']}: " . Exposure::describe($change['after'] ?? []),
                    'changed' => "  ~ {$change['route']}: " . Exposure::describe($change['before'] ?? []) . ' → ' . Exposure::describe($change['after'] ?? []),
                    'gone' => "  - {$change['route']}",
                });
            }
        }
        $anyone = array_keys(array_filter($current->routes, static fn (array $entry): bool => $entry['access'] === 'anyone'));
        if ($anyone !== []) {
            $io->warning(count($anyone) . ' route(s) can be reached by anyone without saying so: ' . implode(', ', array_slice($anyone, 0, 5))
                . (count($anyone) > 5 ? ', …' : '') . '. php bin/console check says how to fix them.');
        }
        $io->writeln('Review who may reach each route in the diff, then commit the file.');

        return self::SUCCESS;
    }

    /**
     * @param array<string, int> $counts
     */
    private static function counts(array $counts): string
    {
        $words = ['public' => 'public', 'user' => 'for signed-in users', 'permission' => 'with a permission', 'anyone' => 'open without saying so'];
        $parts = [];
        foreach ($words as $access => $word) {
            if (($counts[$access] ?? 0) > 0) {
                $parts[] = "{$counts[$access]} {$word}";
            }
        }

        return implode(', ', $parts);
    }
}
