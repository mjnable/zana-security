<?php

declare(strict_types=1);

namespace Zana\Security\Spam;

/**
 * A reserving rule that holds what it judged in one step (2.29): claim()
 * reserves the post, and says, with a Signal, when another request holds the
 * same thing already. check() reads and reserve() writes, so two posts read
 * within the same instant could both pass; claimed at once, only one does.
 *
 * SpamGuardMiddleware claims after the rules let a post through, and refuses
 * the post when a claim's signal brings its points to the threshold. Only
 * what was claimed is released when the handler fails. A rule whose cache
 * cannot claim atomically reserves as before 2.29 and returns null.
 *
 * @api
 */
interface ClaimingSpamRuleInterface extends ReservingSpamRuleInterface
{
    /**
     * Reserve the post, or return why it cannot be: another request holds it.
     */
    public function claim(Submission $submission): ?Signal;
}
