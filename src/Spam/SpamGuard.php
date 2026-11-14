<?php

declare(strict_types=1);

namespace Zana\Security\Spam;

use Closure;
use Psr\Log\LoggerInterface;
use Psr\SimpleCache\CacheInterface;
use Zana\Security\SecurityException;
use Zana\Security\Spam\Rule\BlockedTerms;
use Zana\Security\Spam\Rule\FixedScore;
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

    /** The rules whose reasons hold no text the visitor sent, and so may be recorded (2.24.1). */
    private const array OWN_RULES = [TooManyLinks::class, BlockedTerms::class, RepeatedContent::class, FixedScore::class];

    /** An application rule's name, recorded only when it reads as a name. */
    private const string NAME = '/^[a-z][a-z0-9_.-]{0,39}$/';

    /**
     * @param array<mixed> $forms security.spam.forms
     * @param Closure(class-string<SpamRuleInterface>): SpamRuleInterface $resolve Creates an application's rule
     * @param (Closure(): int)|null $now
     * @param LoggerInterface|null $logger Told when a rule cannot use the cache, or fails after a post was accepted (2.24.1)
     */
    public function __construct(
        private readonly array $forms,
        private readonly ?CacheInterface $cache,
        private readonly Closure $resolve,
        private readonly ?Closure $now = null,
        private readonly ?LoggerInterface $logger = null,
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
        $recordable = [];
        $points = 0;
        foreach ($this->rules($profile) as $rule) {
            $signal = $rule->check($submission);
            if ($signal !== null && $signal->points > 0) {
                $signals[] = $signal;
                $recordable[] = self::recordable($rule, $signal);
                $points += $signal->points;
            }
        }

        return new Verdict($points >= $profile->threshold, $points, $profile->threshold, $signals, $recordable);
    }

    /**
     * Tells the rules that remember what was accepted. The handler has taken
     * the message by then, so a rule that fails is reported, never thrown
     * (2.24.1): the visitor must not be told that a received message failed.
     */
    public function accepted(string $form, Submission $submission): void
    {
        foreach ($this->rules($this->profile($form)) as $rule) {
            if (!$rule instanceof RecordingSpamRuleInterface) {
                continue;
            }
            try {
                $rule->accepted($submission);
            } catch (\Throwable $e) {
                $this->logger?->error('A spam rule failed after a form post was accepted; the post was kept.', ['form' => $form, 'rule' => $rule::class, 'exception' => $e::class]);
            }
        }
    }

    /**
     * What may be recorded of a signal, in SpamRefused and the audit log
     * (2.24.1): Zana's rules give counts and the configured terms, so their
     * reasons are kept; an application's rule may put anything in its
     * reason, the text included, so only its name and points are, and the
     * name only when it reads as one.
     */
    private static function recordable(SpamRuleInterface $rule, Signal $signal): string
    {
        if (in_array($rule::class, self::OWN_RULES, true)) {
            return "{$signal->rule}: {$signal->reason}";
        }
        $name = preg_match(self::NAME, $signal->rule) === 1 ? $signal->rule : $rule::class;

        return "{$name}: {$signal->points} point(s)";
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
            $logger = $this->logger;
            $rules[] = new RepeatedContent(
                $this->cache,
                $profile->duplicateMinutes,
                $profile->duplicateScope,
                $this->now,
                static function (\Throwable $e) use ($logger, $profile): void {
                    $logger?->warning('The spam rule for repeated text could not use the cache, so it found nothing for this post; the other rules still applied.', ['form' => $profile->form, 'exception' => $e::class]);
                },
            );
        }
        foreach ($profile->rules as $class) {
            $rules[] = ($this->resolve)($class);
        }

        return $this->rules[$profile->form] = $rules;
    }
}
