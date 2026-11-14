<?php

declare(strict_types=1);

namespace Zana\Security\Spam\Rule;

use Zana\Security\Spam\Signal;
use Zana\Security\Spam\SpamRuleInterface;
use Zana\Security\Spam\Submission;

/**
 * More links than a message to this form needs (max_links). A link is an
 * http(s):// or www. address, a [url] tag or an <a> element.
 */
final readonly class TooManyLinks implements SpamRuleInterface
{
    private const string LINK = '~(?:https?://|www\.|\[url[=\]]|<a\s)~iu';

    public function __construct(
        private int $max,
    ) {
    }

    public function check(Submission $submission): ?Signal
    {
        $count = (int) preg_match_all(self::LINK, $submission->text());

        return $count > $this->max ? new Signal('links', 1, "{$count} link(s), at most {$this->max}") : null;
    }
}
