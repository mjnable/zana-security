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

    /** @var \WeakMap<Submission, list<ReservingSpamRuleInterface>> What each submission claimed (2.29) */
    private \WeakMap $claimed;

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
        $this->claimed = new \WeakMap();
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
     * Holds what the rules let through while the handler runs (2.25), for
     * the rules that reserve. A rule that fails is logged: the post goes on.
     */
    public function reserve(string $form, Submission $submission): void
    {
        $this->each($form, static fn (ReservingSpamRuleInterface $rule) => $rule->reserve($submission), 'reserve');
    }

    /**
     * Holds what the rules let through, in one step for the rules that claim
     * (2.29), and gives the verdict with what the claims found: another
     * request at the same instant that holds the same post. When that makes
     * the post spam, what this request claimed is released again. Either way,
     * a later release() of this submission frees only what it claimed, never
     * what another request holds. A rule that fails is logged: the post goes
     * on. The rules that reserve without claiming reserve, as with reserve().
     */
    public function claim(string $form, Submission $submission, Verdict $verdict): Verdict
    {
        $profile = $this->profile($form);
        $signals = $verdict->signals;
        $recordable = $verdict->recordable;
        $points = $verdict->points;
        $held = [];
        foreach ($this->rules($profile) as $rule) {
            if (!$rule instanceof ReservingSpamRuleInterface) {
                continue;
            }
            try {
                $signal = $rule instanceof ClaimingSpamRuleInterface ? $rule->claim($submission) : null;
                if (!$rule instanceof ClaimingSpamRuleInterface) {
                    $rule->reserve($submission);
                }
            } catch (\Throwable $e) {
                $this->logger?->error('A spam rule failed to claim a form post; the post went on.', ['form' => $form, 'rule' => $rule::class, 'exception' => $e::class]);
                continue;
            }
            if ($signal === null || $signal->points <= 0) {
                $held[] = $rule;
            } elseif (!in_array($signal, $signals, false)) {   // check() may have found it already: never counted twice
                $signals[] = $signal;
                $recordable[] = self::recordable($rule, $signal);
                $points += $signal->points;
            }
        }
        $this->claimed[$submission] = $held;

        $judged = new Verdict($points >= $profile->threshold, $points, $profile->threshold, $signals, $recordable);
        if ($judged->spam) {
            $this->release($form, $submission);
        }

        return $judged;
    }

    /**
     * The handler answered with an error or failed: frees what reserve() held
     * (2.25), so the corrected form is not taken for a repeat. For a
     * submission claimed with claim() (2.29), only what it claimed.
     */
    public function release(string $form, Submission $submission): void
    {
        $held = $this->claimed[$submission] ?? null;
        if ($held !== null) {
            $this->claimed[$submission] = [];   // released: a second release frees nothing, least of all another's hold
        }
        $this->each($form, static fn (ReservingSpamRuleInterface $rule) => $held === null || in_array($rule, $held, true) ? $rule->release($submission) : null, 'release');
    }

    /**
     * @param Closure(ReservingSpamRuleInterface): void $call
     */
    private function each(string $form, Closure $call, string $what): void
    {
        foreach ($this->rules($this->profile($form)) as $rule) {
            if (!$rule instanceof ReservingSpamRuleInterface) {
                continue;
            }
            try {
                $call($rule);
            } catch (\Throwable $e) {
                $this->logger?->error("A spam rule failed to {$what} a form post; the post went on.", ['form' => $form, 'rule' => $rule::class, 'exception' => $e::class]);
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
                static function (\Throwable $e, string $operation) use ($logger, $profile): void {
                    $logger?->warning($operation === 'read'
                        ? 'The spam rule for repeated text could not read the cache, so it found nothing for this post; the other rules still applied.'
                        : "The spam rule for repeated text could not {$operation} its entry in the cache, so a repeat of this post may not be caught.", ['form' => $profile->form, 'exception' => $e::class]);
                },
            );
        }
        foreach ($profile->rules as $class) {
            $rules[] = ($this->resolve)($class);
        }

        return $this->rules[$profile->form] = $rules;
    }
}
