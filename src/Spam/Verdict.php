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
     */
    public function __construct(
        public bool $spam,
        public int $points,
        public int $threshold,
        public array $signals,
    ) {
    }

    /**
     * @return list<string> Each rule that found something, as "rule: reason"
     */
    public function reasons(): array
    {
        return array_map(static fn (Signal $s): string => "{$s->rule}: {$s->reason}", $this->signals);
    }
}
