<?php

declare(strict_types=1);

namespace Zana\Security\Inspection;

use Zana\Configuration\ConfigurationInterface;
use Zana\Routing\Router;
use Zana\Security\Internal\HandlerReflection;

/**
 * Who may reach each route: the reviewed baseline of what an application
 * exposes (2.23, FE-68 layer 4, ADR-033), security/exposure.json, committed.
 * `security:exposure` shows what changed and writes nothing; only --init and
 * --update record it. `check` compares and never writes, so a change is
 * approved only by someone recording it, in a commit others review.
 *
 * The file is deterministic: routes sorted by path then methods, permissions
 * sorted, nothing from the environment or the machine (no paths, no dates).
 * Only what the command writes is accepted as a baseline (asWritten).
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

    private const string ABOUT = 'Who may reach each route, as reviewed. Do not edit it: php bin/console security:exposure shows what changed, and --update records it once reviewed. check reports every route that differs from it.';

    private const int FLAGS = JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR;

    /** Each access, with its fields: "text" or "list" is required, "text?" optional. */
    private const array FIELDS = [
        'public' => ['reason' => 'text'],
        'user' => ['middleware' => 'text?'],
        'permission' => ['permissions' => 'list', 'middleware' => 'text?'],
        'anyone' => ['problem' => 'text'],
    ];

    /**
     * @param array<string, array<string, string|list<string>>> $routes By "METHODS /path", sorted by path
     * @param array<string, string|null> $locations Where each route's handler is written, for a finding
     * @param bool $asWritten Read from a file exactly as security:exposure writes it (no hand edit)
     */
    private function __construct(
        public array $routes,
        public array $locations = [],
        public bool $asWritten = true,
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
        if (($data['format'] ?? null) !== self::FORMAT) {
            throw new \UnexpectedValueException('its "format" is not ' . self::FORMAT . ', the only one this version reads');
        }
        $routes = [];
        foreach ($data['routes'] as $key => $entry) {
            if (!is_string($key)) {
                throw new \UnexpectedValueException('the entry ' . $key . ' is not named by its methods and path, such as "GET /about"');
            }
            $routes[$key] = self::validEntry(json_encode($key, self::FLAGS), $entry);
        }
        $exposure = new self(self::sorted($routes));

        // Exactly as security:exposure writes it, but for what Git and editors change: a byte order mark, CRLF line ends.
        $written = str_replace("\r\n", "\n", $raw) === $exposure->encode();

        return new self($exposure->routes, [], $written);
    }

    /**
     * One recorded entry, which must be one security:exposure writes: a known
     * access, with the fields it needs and no other.
     *
     * @return array<string, string|list<string>>
     */
    private static function validEntry(string $name, mixed $entry): array
    {
        if (!is_array($entry) || !is_string($entry['access'] ?? null)) {
            throw new \UnexpectedValueException("the entry {$name} has no \"access\"");
        }
        $fields = self::FIELDS[$entry['access']] ?? null;
        if ($fields === null) {
            throw new \UnexpectedValueException("the entry {$name} has the access \"{$entry['access']}\", which is none of " . implode(', ', array_keys(self::FIELDS)));
        }
        $clean = [];
        foreach ($entry as $field => $value) {
            if ($field === 'access') {
                $clean['access'] = $entry['access'];
            } elseif (!is_string($field) || !array_key_exists($field, $fields)) {
                throw new \UnexpectedValueException("the entry {$name} has a field " . json_encode($field, self::FLAGS) . " that \"{$entry['access']}\" does not have");
            } elseif ($fields[$field] === 'list') {
                if (!is_array($value) || $value === [] || !array_is_list($value) || array_filter($value, static fn (mixed $v): bool => is_string($v) && trim($v) !== '') !== $value) {
                    throw new \UnexpectedValueException("the entry {$name} has \"{$field}\" that is not a list of names");
                }
                $clean[$field] = self::sortedList($value);
            } else {
                if (!is_string($value) || trim($value) === '') {
                    throw new \UnexpectedValueException("the entry {$name} has \"{$field}\" that is not text");
                }
                $clean[$field] = $value;
            }
        }
        foreach ($fields as $field => $kind) {
            if (!str_ends_with($kind, '?') && !isset($clean[$field])) {
                throw new \UnexpectedValueException("the entry {$name} is \"{$entry['access']}\" without its \"{$field}\"");
            }
        }
        ksort($clean);

        return $clean;
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
