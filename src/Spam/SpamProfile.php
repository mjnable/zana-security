<?php

declare(strict_types=1);

namespace Zana\Security\Spam;

/**
 * The spam rules of one form, from security.spam.forms.<form> (2.24,
 * FE-63), checked strictly: a mistyped setting would otherwise turn a rule
 * off without anyone noticing.
 *
 *     'contact' => [
 *         'max_links' => 2,                              // more is spam
 *         'blocked_terms' => ['casino', 'crypto investment'],
 *         'duplicate_minutes' => 30,                     // the same text again within 30 minutes (a PSR-16 cache)
 *         'duplicate_scope' => 'client',                 // or 'everyone'
 *         'fields' => ['message'],                       // the fields read; all text fields when absent
 *         'rules' => [App\Spam\NoShouting::class],       // the application's own
 *         'threshold' => 1,                              // the points that make a post spam
 *         'redirect' => '/en/contact/thanks',            // else security.csrf.spam_redirect, else 403
 *     ],
 *
 * @api
 */
final readonly class SpamProfile
{
    public const array SETTINGS = ['max_links', 'blocked_terms', 'duplicate_minutes', 'duplicate_scope', 'fields', 'rules', 'threshold', 'redirect'];

    /**
     * @param list<string> $blockedTerms
     * @param 'client'|'everyone' $duplicateScope
     * @param list<string>|null $fields
     * @param list<class-string<SpamRuleInterface>> $rules
     */
    private function __construct(
        public string $form,
        public ?int $maxLinks,
        public array $blockedTerms,
        public ?int $duplicateMinutes,
        public string $duplicateScope,
        public ?array $fields,
        public array $rules,
        public int $threshold,
        public ?string $redirect,
    ) {
    }

    /**
     * The profile, or null with each reason in $problems.
     *
     * @param list<string> $problems
     */
    public static function fromConfig(string $form, mixed $config, array &$problems): ?self
    {
        $at = "security.spam.forms.{$form}";
        if (!is_array($config)) {
            $problems[] = "{$at} is not a list of settings.";

            return null;
        }
        $before = count($problems);
        foreach (array_keys($config) as $key) {
            if (!in_array($key, self::SETTINGS, true)) {
                $problems[] = "{$at} has an unknown setting " . json_encode($key) . '; the settings are ' . implode(', ', self::SETTINGS) . '.';
            }
        }
        $maxLinks = self::int($config, 'max_links', 0, $at, $problems);
        $minutes = self::int($config, 'duplicate_minutes', 1, $at, $problems);
        $threshold = self::int($config, 'threshold', 1, $at, $problems) ?? 1;
        $terms = self::names($config, 'blocked_terms', $at, $problems) ?? [];
        $fields = self::names($config, 'fields', $at, $problems);

        $scope = $config['duplicate_scope'] ?? 'client';
        if ($scope !== 'client' && $scope !== 'everyone') {
            $problems[] = "{$at}.duplicate_scope is " . json_encode($scope) . ', not "client" or "everyone".';
            $scope = 'client';
        }

        $rules = [];
        foreach (self::names($config, 'rules', $at, $problems) ?? [] as $class) {
            if (!class_exists($class) || !is_a($class, SpamRuleInterface::class, true)) {
                $problems[] = "{$at}.rules names {$class}, which is not a class implementing " . SpamRuleInterface::class . '.';
                continue;
            }
            $rules[] = $class;
        }

        $redirect = $config['redirect'] ?? null;
        if ($redirect !== null && (!is_string($redirect) || !str_starts_with($redirect, '/') || str_starts_with($redirect, '//') || str_contains($redirect, '\\'))) {
            $problems[] = "{$at}.redirect must be a path on this site, such as /contact/thanks: " . json_encode($redirect) . ' could send visitors elsewhere.';
            $redirect = null;
        }

        if ($maxLinks === null && $terms === [] && $minutes === null && $rules === [] && count($problems) === $before) {
            $problems[] = "{$at} sets no rule, so it refuses nothing: set max_links, blocked_terms, duplicate_minutes or rules.";
        }
        if (count($problems) > $before) {
            return null;
        }

        return new self($form, $maxLinks, $terms, $minutes, $scope, $fields, $rules, $threshold, $redirect);
    }

    /**
     * @param array<mixed> $config
     * @param list<string> $problems
     */
    private static function int(array $config, string $key, int $min, string $at, array &$problems): ?int
    {
        $value = $config[$key] ?? null;
        if ($value === null) {
            return null;
        }
        if (!is_int($value) || $value < $min) {
            $problems[] = "{$at}.{$key} is " . json_encode($value) . ", not a whole number of at least {$min}.";

            return null;
        }

        return $value;
    }

    /**
     * @param array<mixed> $config
     * @param list<string> $problems
     * @return list<string>|null
     */
    private static function names(array $config, string $key, string $at, array &$problems): ?array
    {
        $value = $config[$key] ?? null;
        if ($value === null) {
            return null;
        }
        if (!is_array($value) || !array_is_list($value) || array_filter($value, static fn (mixed $v): bool => is_string($v) && trim($v) !== '') !== $value) {
            $problems[] = "{$at}.{$key} is not a list of names.";

            return null;
        }

        return $value;
    }
}
