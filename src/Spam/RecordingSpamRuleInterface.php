<?php

declare(strict_types=1);

namespace Zana\Security\Spam;

/**
 * A rule that remembers what was accepted, such as the same text sent
 * again. accepted() is called only when the handler answered without an
 * error, so a person who corrects a mistake in the form and sends the same
 * message again is not taken for a bot.
 *
 * @api
 */
interface RecordingSpamRuleInterface extends SpamRuleInterface
{
    public function accepted(Submission $submission): void;
}
