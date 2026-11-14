<?php

declare(strict_types=1);

namespace Zana\Security\Spam;

/**
 * A recording rule that also holds what it judged while the handler runs
 * (2.25): reserve() right after the rules let a post through, so the same
 * text sent at the same moment is caught; release() when the handler
 * answered with an error or failed, so a corrected form goes through.
 * accepted() still follows a handler that answered without an error.
 *
 * PSR-16 has no atomic "add if absent", so two posts read within the same
 * instant can still both pass: the reservation narrows that window to the
 * time between one read and one write.
 *
 * @api
 */
interface ReservingSpamRuleInterface extends RecordingSpamRuleInterface
{
    public function reserve(Submission $submission): void;

    public function release(Submission $submission): void;
}
