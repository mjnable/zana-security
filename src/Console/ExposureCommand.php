<?php

declare(strict_types=1);

namespace Zana\Security\Console;

use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Style\SymfonyStyle;
use Zana\Configuration\ConfigurationInterface;
use Zana\Console\Command;
use Zana\Core\ApplicationInterface;
use Zana\Routing\Router;
use Zana\Security\Inspection\Exposure;

/**
 * security:exposure (2.23, FE-68 layer 4): who may reach each route, against
 * the reviewed baseline security/exposure.json. Reporting and recording are
 * separate, so a change is never approved by running the command:
 *
 *     php bin/console security:exposure            # what changed; writes nothing, exit 1 when anything did
 *     php bin/console security:exposure --init     # records the first baseline, only when there is none
 *     php bin/console security:exposure --update   # records the changes into the existing baseline, once reviewed
 */
#[AsCommand(name: 'security:exposure', description: 'Show who may reach each route against the reviewed baseline, security/exposure.json; --init or --update records it')]
final class ExposureCommand extends Command
{
    protected function configure(): void
    {
        $this
            ->addOption('init', null, InputOption::VALUE_NONE, 'Record the first baseline; refused when one exists')
            ->addOption('update', null, InputOption::VALUE_NONE, 'Record the changes into the existing baseline, once you have reviewed them');
    }

    public function handle(InputInterface $input, ApplicationInterface $application, SymfonyStyle $io): int
    {
        $init = (bool) $input->getOption('init');
        $update = (bool) $input->getOption('update');
        if ($init && $update) {
            $io->error('Pass --init or --update, not both.');

            return self::FAILURE;
        }
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

        if (!is_file($path)) {
            if ($update) {
                $io->error("There is no baseline to update. Review the routes with security:exposure, then record the first baseline with --init.");

                return self::FAILURE;
            }
            if (!$init) {
                $io->writeln("There is no reviewed baseline yet ({$file}). Who may reach each route now:");
                foreach ($current->routes as $route => $entry) {
                    $io->writeln("  {$route}: " . Exposure::describe($entry));
                }
                $this->warnAnyone($current, $io);
                $io->writeln('Nothing was written. Once you have reviewed the list, record it with security:exposure --init, and commit the file.');

                return self::FAILURE;
            }

            return $this->write($current, $path, $io, 'Recorded the first baseline, ' . $file . ': ' . count($current->routes) . ' route(s), ' . self::counts($current) . '.', []);
        }

        if ($init) {
            $io->error("{$file} exists. To record changes into it, review them with security:exposure, then run --update.");

            return self::FAILURE;
        }
        try {
            $recorded = Exposure::read($path);
        } catch (\UnexpectedValueException $e) {
            $io->error([
                "{$file} is not a baseline of routes: {$e->getMessage()}.",
                'Nothing was written: replacing it would record every route unreviewed. Restore it from Git; if it is lost, delete it, review the routes with security:exposure, and record them with --init.',
            ]);

            return self::FAILURE;
        }

        $changes = $current->changesSince($recorded);
        if (!$update) {
            if (!$recorded->asWritten) {
                $io->warning("{$file} is not as security:exposure writes it: it was edited by hand, or a route is named twice.");
            }
            if ($changes === [] && $recorded->asWritten) {
                $io->success("Every route matches the reviewed baseline {$file}: " . count($current->routes) . ' route(s).');

                return self::SUCCESS;
            }
            if ($changes !== []) {
                $io->writeln(count($changes) . " route(s) differ from the reviewed baseline {$file}:");
                self::listChanges($changes, $io);
            }
            $this->warnAnyone($current, $io);
            $io->writeln('Nothing was written. Review each change; once reviewed, record them with security:exposure --update, and commit the file.');

            return self::FAILURE;
        }

        if ($changes === [] && $recorded->asWritten) {
            $io->success("Nothing to record: every route matches the reviewed baseline {$file}.");

            return self::SUCCESS;
        }

        return $this->write(
            $current,
            $path,
            $io,
            $changes === []
                ? "Rewrote {$file} as the command writes it; no route changed."
                : 'Recorded ' . count($changes) . " change(s) in {$file}:",
            $changes,
        );
    }

    /**
     * @param list<array{route: string, change: 'new'|'changed'|'gone', before: array<string, string|list<string>>|null, after: array<string, string|list<string>>|null}> $changes
     */
    private function write(Exposure $current, string $path, SymfonyStyle $io, string $done, array $changes): int
    {
        $folder = dirname($path);
        if (!is_dir($folder) && !mkdir($folder, 0o775, true) && !is_dir($folder)) {
            $io->error('Cannot create the folder of ' . Exposure::FILE . '.');

            return self::FAILURE;
        }
        if (file_put_contents($path, $current->encode()) === false) {
            $io->error('Cannot write ' . Exposure::FILE . '.');

            return self::FAILURE;
        }
        $io->writeln($done);
        self::listChanges($changes, $io);
        $this->warnAnyone($current, $io);
        $io->writeln('Commit the file: the commit is the record of the review.');

        return self::SUCCESS;
    }

    /**
     * @param list<array{route: string, change: 'new'|'changed'|'gone', before: array<string, string|list<string>>|null, after: array<string, string|list<string>>|null}> $changes
     */
    private static function listChanges(array $changes, SymfonyStyle $io): void
    {
        foreach ($changes as $change) {
            $io->writeln(match ($change['change']) {
                'new' => "  + {$change['route']}: " . Exposure::describe($change['after'] ?? []),
                'changed' => "  ~ {$change['route']}: " . Exposure::describe($change['before'] ?? []) . ' → ' . Exposure::describe($change['after'] ?? []),
                'gone' => "  - {$change['route']}",
            });
        }
    }

    private function warnAnyone(Exposure $current, SymfonyStyle $io): void
    {
        $anyone = array_keys(array_filter($current->routes, static fn (array $entry): bool => $entry['access'] === 'anyone'));
        if ($anyone !== []) {
            $io->warning(count($anyone) . ' route(s) can be reached by anyone without saying so: ' . implode(', ', array_slice($anyone, 0, 5))
                . (count($anyone) > 5 ? ', …' : '') . '. php bin/console check says how to fix them.');
        }
    }

    private static function counts(Exposure $current): string
    {
        $counts = array_count_values(array_map(static fn (array $entry): string => is_string($entry['access']) ? $entry['access'] : 'anyone', $current->routes));
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
