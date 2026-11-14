<?php

declare(strict_types=1);

namespace Zana\Security\Spam\Rule;

use Zana\Security\Spam\Signal;
use Zana\Security\Spam\SpamRuleInterface;
use Zana\Security\Spam\Submission;

/**
 * For tests: the same points for every submission, so a test can make a
 * form's rules call any post spam, or none, and test what follows.
 *
 *     $this->withConfig(['security.spam.forms.contact.rules' => [FixedScore::class]]);   // every post is spam
 */
final readonly class FixedScore implements SpamRuleInterface
{
    public function __construct(
        private int $points = 1,
        private string $reason = 'a fixed score, for tests',
    ) {
    }

    public function check(Submission $submission): ?Signal
    {
        return $this->points > 0 ? new Signal('fixed', $this->points, $this->reason) : null;
    }
}
