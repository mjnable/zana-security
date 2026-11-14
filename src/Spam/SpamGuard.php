<?php

declare(strict_types=1);

namespace Zana\Security\Spam;

use Closure;
use Psr\SimpleCache\CacheInterface;
use Zana\Security\SecurityException;
use Zana\Security\Spam\Rule\BlockedTerms;
use Zana\Security\Spam\Rule\RepeatedContent;
use Zana\Security\Spam\Rule\TooManyLinks;

/**
 * Judges a form's submissions by its rules (2.24, FE-63): each rule that
 * finds something gives points, and a submission whose points reach the
 * form's threshold is spam. SpamGuardMiddleware then treats it as it treats
 * a filled honeypot.
 *
 * @api
 */
final class SpamGuard
{
    /** @var array<string, list<SpamRuleInterface>> */
    private array $rules = [];

    /** @var array<string, SpamProfile> */
    private array $profiles = [];

    /**
     * @param array<mixed> $forms security.spam.forms
     * @param Closure(class-string<SpamRuleInterface>): SpamRuleInterface $resolve Creates an application's rule
     * @param (Closure(): int)|null $now
     */
    public function __construct(
        private readonly array $forms,
        private readonly ?CacheInterface $cache,
        private readonly Closure $resolve,
        private readonly ?Closure $now = null,
    ) {
    }

    /**
     * What is wrong with the forms' settings, for `check`.
     *
     * @param array<mixed> $forms
     * @return list<string>
     */
    public static function problems(array $forms, bool $hasCache): array
    {
        $problems = [];
        foreach ($forms as $form => $config) {
            $profile = SpamProfile::fromConfig((string) $form, $config, $problems);
            if ($profile?->duplicateMinutes !== null && !$hasCache) {
                $problems[] = "security.spam.forms.{$form}.duplicate_minutes needs a PSR-16 cache (Psr\\SimpleCache\\CacheInterface) to remember what was accepted.";
            }
        }

        return $problems;
    }

    public function has(string $form): bool
    {
        return array_key_exists($form, $this->forms);
    }

    /**
     * @throws SecurityException When the form has no rules, or wrong ones: a guard that cannot judge refuses nothing
     */
    public function profile(string $form): SpamProfile
    {
        if (isset($this->profiles[$form])) {
            return $this->profiles[$form];
        }
        if (!$this->has($form)) {
            throw new SecurityException("#[SpamRules('{$form}')] names a form without rules: add security.spam.forms.{$form}.");
        }
        $problems = [];
        $profile = SpamProfile::fromConfig($form, $this->forms[$form], $problems);
        if ($profile === null) {
            throw new SecurityException(implode(' ', $problems));
        }

        return $this->profiles[$form] = $profile;
    }

    public function judge(string $form, Submission $submission): Verdict
    {
        $profile = $this->profile($form);
        $signals = [];
        $points = 0;
        foreach ($this->rules($profile) as $rule) {
            $signal = $rule->check($submission);
            if ($signal !== null && $signal->points > 0) {
                $signals[] = $signal;
                $points += $signal->points;
            }
        }

        return new Verdict($points >= $profile->threshold, $points, $profile->threshold, $signals);
    }

    /**
     * Tells the rules that remember what was accepted.
     */
    public function accepted(string $form, Submission $submission): void
    {
        foreach ($this->rules($this->profile($form)) as $rule) {
            if ($rule instanceof RecordingSpamRuleInterface) {
                $rule->accepted($submission);
            }
        }
    }

    /**
     * @return list<SpamRuleInterface>
     */
    private function rules(SpamProfile $profile): array
    {
        if (isset($this->rules[$profile->form])) {
            return $this->rules[$profile->form];
        }
        $rules = [];
        if ($profile->maxLinks !== null) {
            $rules[] = new TooManyLinks($profile->maxLinks);
        }
        if ($profile->blockedTerms !== []) {
            $rules[] = new BlockedTerms($profile->blockedTerms);
        }
        if ($profile->duplicateMinutes !== null) {
            if ($this->cache === null) {
                throw new SecurityException("security.spam.forms.{$profile->form}.duplicate_minutes needs a PSR-16 cache (Psr\\SimpleCache\\CacheInterface).");
            }
            $rules[] = new RepeatedContent($this->cache, $profile->duplicateMinutes, $profile->duplicateScope, $this->now);
        }
        foreach ($profile->rules as $class) {
            $rules[] = ($this->resolve)($class);
        }

        return $this->rules[$profile->form] = $rules;
    }
}
