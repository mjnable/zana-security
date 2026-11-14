<?php

declare(strict_types=1);

namespace Zana\Security\Spam\Rule;

use Zana\Security\Spam\Signal;
use Zana\Security\Spam\SpamRuleInterface;
use Zana\Security\Spam\Submission;

/**
 * Words or phrases that only spam uses on this form (blocked_terms), found
 * as whole words, whatever their case and spacing: "casino" matches
 * "Casino" and "CASINO!", not "occasionally".
 */
final readonly class BlockedTerms implements SpamRuleInterface
{
    /** @var array<string, string> Each term, by its pattern */
    private array $patterns;

    /**
     * @param list<string> $terms
     */
    public function __construct(array $terms)
    {
        $patterns = [];
        foreach ($terms as $term) {
            $words = preg_split('/\s+/u', trim(mb_strtolower($term, 'UTF-8'))) ?: [];
            $words = array_values(array_filter($words, static fn (string $w): bool => $w !== ''));
            if ($words !== []) {
                $body = implode('\s+', array_map(static fn (string $w): string => preg_quote($w, '/'), $words));
                $patterns['/(?<![\p{L}\p{N}])' . $body . '(?![\p{L}\p{N}])/u'] = implode(' ', $words);
            }
        }
        $this->patterns = $patterns;
    }

    public function check(Submission $submission): ?Signal
    {
        $text = $submission->normalized();
        $found = [];
        foreach ($this->patterns as $pattern => $term) {
            if (preg_match($pattern, $text) === 1) {
                $found[] = $term;
            }
        }

        return $found === [] ? null : new Signal('blocked_terms', 1, 'blocked term(s): ' . implode(', ', $found));
    }
}
