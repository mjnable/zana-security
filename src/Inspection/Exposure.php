<?php

declare(strict_types=1);

namespace Zana\Security\Inspection;

use Zana\Configuration\ConfigurationInterface;
use Zana\Routing\Router;
use Zana\Security\Internal\HandlerReflection;

/**
 * Who may reach each route: the reviewed list of what an application exposes
 * (2.23, FE-68 layer 4, ADR-033). `php bin/console security:exposure` writes
 * it to security/exposure.json, which is committed, so each change is
 * reviewed in a diff; `check` reports a route that is new or whose access
 * changed until the file is written again.
 *
 * Each route is read through RouteAccess, as `check` and the attacks of
 * mj-zana/testing read it, and recorded as what it does, not what it says:
 *
 *     "GET /api/patients": {"access": "permission", "permissions": ["patients.read"]}
 *     "GET /manage": {"access": "user", "middleware": "App\\Web\\SignedIn"}
 *     "POST /contact": {"access": "public", "reason": "The public website"}
 *     "GET /report": {"access": "anyone", "problem": "It requires a user, but AuthorizationMiddleware is not on the route."}
 *
 * @api
 */
final readonly class Exposure
{
    public const string FILE = 'security/exposure.json';

    public const int FORMAT = 1;

    /** About 150 bytes a route: room for over 10,000 routes. */
    private const int MAX_BYTES = 2 << 20;

    private const string ABOUT = 'Who may reach each route. Written by php bin/console security:exposure: review each change in the diff, then commit it. check reports a route that is new, or whose access changed, until this file is written again.';

    private const int FLAGS = JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR;

    /**
     * @param array<string, array<string, string|list<string>>> $routes By "METHODS /path", sorted by path
     * @param array<string, string|null> $locations Where each route's handler is written, for a finding
     */
    private function __construct(
        public array $routes,
        public array $locations = [],
    ) {
    }

    /**
     * The application's routes, as they are now.
     */
    public static function of(Router $router, ConfigurationInterface $config): self
    {
        $global = array_values(array_filter($config->array('http.middleware', []), is_string(...)));
        $declared = RouteAccess::declaredMiddleware($config);
        $routes = [];
        $locations = [];
        foreach ($router->routes() as $route) {
            $base = implode('|', $route->methods) . ' ' . $route->path;
            $key = $base;
            for ($n = 2; isset($routes[$key]); $n++) {   // the same route twice: both are listed
                $key = "{$base} ({$n})";
            }
            $routes[$key] = self::entry(RouteAccess::of($route, $global, $declared));
            $locations[$key] = HandlerReflection::location($route->handler);
        }

        return new self(self::sorted($routes), $locations);
    }

    /**
     * The list recorded in a file.
     *
     * @throws \UnexpectedValueException When it is not such a list
     */
    public static function read(string $file): self
    {
        $size = @filesize($file);
        if ($size !== false && $size > self::MAX_BYTES) {
            throw new \UnexpectedValueException('it is larger than ' . (self::MAX_BYTES >> 20) . ' MB, far more than a list of routes needs');
        }
        $raw = @file_get_contents($file);
        if ($raw === false) {
            throw new \UnexpectedValueException('it cannot be read');
        }
        if (str_starts_with($raw, "\u{FEFF}")) {   // as some Windows editors save it
            $raw = substr($raw, 3);
        }
        try {
            $data = json_decode($raw, true, 16, JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw new \UnexpectedValueException("it is not valid JSON ({$e->getMessage()})");
        }
        if (!is_array($data) || !is_array($data['routes'] ?? null) || ($data['routes'] !== [] && array_is_list($data['routes']))) {
            throw new \UnexpectedValueException('it has no "routes" object, of each route by its methods and path');
        }
        $routes = [];
        foreach ($data['routes'] as $key => $entry) {
            if (!is_string($key)) {
                throw new \UnexpectedValueException('the entry ' . $key . ' is not named by its methods and path, such as "GET /about"');
            }
            if (!is_array($entry) || !is_string($entry['access'] ?? null)) {
                throw new \UnexpectedValueException('the entry ' . json_encode($key, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . ' has no "access"');
            }
            $clean = [];
            foreach ($entry as $field => $value) {
                if (is_string($field) && is_string($value)) {
                    $clean[$field] = $value;
                } elseif (is_string($field) && is_array($value) && array_is_list($value) && array_filter($value, is_string(...)) === $value) {
                    $clean[$field] = self::sortedList($value);
                } else {
                    throw new \UnexpectedValueException('the entry ' . json_encode($key, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . ' has a field that is neither text nor a list of text');
                }
            }
            ksort($clean);
            $routes[$key] = $clean;
        }

        return new self(self::sorted($routes));
    }

    /**
     * The file's contents: one line per route, so a review reads the diff
     * route by route.
     */
    public function encode(): string
    {
        $lines = [];
        foreach ($this->routes as $key => $entry) {
            $fields = [];
            foreach ($entry as $field => $value) {
                $fields[] = json_encode($field, self::FLAGS) . ': ' . json_encode($value, self::FLAGS);
            }
            $lines[] = '        ' . json_encode($key, self::FLAGS) . ': {' . implode(', ', $fields) . '}';
        }

        return "{\n"
            . '    "about": ' . json_encode(self::ABOUT, self::FLAGS) . ",\n"
            . '    "format": ' . self::FORMAT . ",\n"
            . '    "routes": ' . ($lines === [] ? '{}' : "{\n" . implode(",\n", $lines) . "\n    }") . "\n"
            . "}\n";
    }

    /**
     * What changed since the recorded list, route by route, in path order.
     *
     * @return list<array{route: string, change: 'new'|'changed'|'gone', before: array<string, string|list<string>>|null, after: array<string, string|list<string>>|null}>
     */
    public function changesSince(self $recorded): array
    {
        $changes = [];
        foreach ($this->routes as $key => $entry) {
            $before = $recorded->routes[$key] ?? null;
            if ($before === null) {
                $changes[$key] = ['route' => $key, 'change' => 'new', 'before' => null, 'after' => $entry];
            } elseif ($before !== $entry) {
                $changes[$key] = ['route' => $key, 'change' => 'changed', 'before' => $before, 'after' => $entry];
            }
        }
        foreach ($recorded->routes as $key => $entry) {
            if (!isset($this->routes[$key])) {
                $changes[$key] = ['route' => $key, 'change' => 'gone', 'before' => $entry, 'after' => null];
            }
        }

        return array_values(self::sorted($changes));
    }

    /**
     * Who may reach a route, in words: "anyone (public: …)", "signed-in
     * users", "users with patients.read".
     *
     * @param array<string, string|list<string>> $entry
     */
    public static function describe(array $entry): string
    {
        $by = is_string($entry['middleware'] ?? null) ? " (by {$entry['middleware']})" : '';
        $permissions = is_array($entry['permissions'] ?? null) ? $entry['permissions'] : [];

        return match ($entry['access'] ?? null) {
            'public' => 'anyone (public: "' . (is_string($entry['reason'] ?? null) ? $entry['reason'] : '') . '")',
            'user' => "signed-in users{$by}",
            'permission' => 'users with ' . implode(' and ', $permissions) . $by,
            'anyone' => 'anyone (' . lcfirst(rtrim(is_string($entry['problem'] ?? null) ? $entry['problem'] : 'nothing protects it', '.')) . ')',
            default => json_encode($entry, self::FLAGS),
        };
    }

    /**
     * @return array<string, string|list<string>>
     */
    private static function entry(RouteAccess $access): array
    {
        if ($access->needsUser()) {
            $entry = $access->requiresUser && $access->authorized && $access->permissions !== []
                ? ['access' => 'permission', 'permissions' => self::sortedList($access->permissions)]
                : ['access' => 'user'];
            if ($access->application !== null) {
                $entry['middleware'] = $access->application;
            }
        } elseif ($access->requiresUser) {
            $entry = ['access' => 'anyone', 'problem' => 'It requires a user, but AuthorizationMiddleware is not on the route.'];
        } elseif ($access->public !== null) {
            $entry = ['access' => 'public', 'reason' => $access->public];
        } else {
            $entry = ['access' => 'anyone', 'problem' => 'It does not say who may reach it.'];
        }
        ksort($entry);

        return $entry;
    }

    /**
     * By path, then by methods, so a route's methods stay beside it.
     *
     * @template T
     * @param array<string, T> $routes
     * @return array<string, T>
     */
    private static function sorted(array $routes): array
    {
        uksort($routes, static function (string $a, string $b): int {
            $path = static fn (string $key): string => substr($key, (int) strpos($key, ' ') + 1);

            return [$path($a), $a] <=> [$path($b), $b];
        });

        return $routes;
    }

    /**
     * @param list<string> $list
     * @return list<string>
     */
    private static function sortedList(array $list): array
    {
        $list = array_values(array_unique($list));
        sort($list);

        return $list;
    }
}
