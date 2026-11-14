<?php

declare(strict_types=1);

namespace Zana\Security\Spam;

/**
 * What one rule found in a submission: its points towards the form's
 * threshold, and why, in words a person reviewing refused posts can read.
 *
 * @api
 */
final readonly class Signal
{
    /**
     * @param string $rule A short, stable name, such as "links"
     */
    public function __construct(
        public string $rule,
        public int $points,
        public string $reason,
    ) {
    }
}
