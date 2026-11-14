<?php

declare(strict_types=1);

namespace Zana\Security\Spam;

/**
 * One spam rule (2.24, FE-63). An application adds its own by naming the
 * class in a form's "rules"; it is taken from the container when registered
 * there, otherwise created without arguments.
 *
 *     final class NoShouting implements SpamRuleInterface
 *     {
 *         public function check(Submission $submission): ?Signal
 *         {
 *             $text = $submission->text();
 *             return strlen($text) > 40 && strtoupper($text) === $text ? new Signal('shouting', 1, 'all in capitals') : null;
 *         }
 *     }
 *
 * @api
 */
interface SpamRuleInterface
{
    /**
     * What the rule finds, or null when nothing.
     */
    public function check(Submission $submission): ?Signal;
}
