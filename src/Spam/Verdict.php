<?php

declare(strict_types=1);

namespace Zana\Security\Spam;

/**
 * The rules' judgement of one submission: spam when their points reach the
 * form's threshold.
 *
 * @api
 */
final readonly class Verdict
{
    /**
     * @param list<Signal> $signals
     * @param list<string> $recordable What may be recorded of each signal, as SpamGuard decides (2.24.1)
     */
    public function __construct(
        public bool $spam,
        public int $points,
        public int $threshold,
        public array $signals,
        public array $recordable = [],
    ) {
    }

    /**
     * Each rule that found something, as "rule: reason", for the
     * application's own use. An application's rule may put anything in its
     * reason, so never record these: record recordable() instead.
     *
     * @return list<string>
     */
    public function reasons(): array
    {
        return array_map(static fn (Signal $s): string => "{$s->rule}: {$s->reason}", $this->signals);
    }

    /**
     * What may be recorded, as in SpamRefused and the audit log: Zana's
     * rules with their reasons, an application's rule by name and points
     * only, so no text the visitor sent is kept (2.24.1).
     *
     * @return list<string>
     */
    public function recordable(): array
    {
        return $this->recordable;
    }
}
