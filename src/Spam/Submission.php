<?php

declare(strict_types=1);

namespace Zana\Security\Spam;

use Psr\Http\Message\ServerRequestInterface;
use Zana\Security\CsrfTokens;

/**
 * What a visitor sent with a form, as the spam rules read it (2.24, FE-63):
 * its text fields, by name, and who sent it.
 *
 * @api
 */
final readonly class Submission
{
    /**
     * @param array<string, string> $fields Text fields by name; a list is flattened as name[0], name[1]
     * @param string $client Who sent it: "user:<id>" when signed in, else "ip:<address>"
     */
    public function __construct(
        public string $form,
        public array $fields,
        public string $client,
    ) {
    }

    /**
     * The form's text fields from a request. The CSRF token, the form name
     * and the honeypot are left out: they change on every post, or are empty.
     *
     * @param list<string>|null $only The fields to read (by name, a list field by its name without brackets); all when null
     */
    public static function fromRequest(ServerRequestInterface $request, string $form, ?array $only = null, ?string $honeypot = null, ?string $userId = null): self
    {
        $body = $request->getParsedBody();
        $fields = [];
        foreach (is_array($body) ? $body : [] as $name => $value) {
            $name = (string) $name;
            if (in_array($name, [CsrfTokens::FIELD, CsrfTokens::FORM_FIELD, $honeypot], true) || ($only !== null && !in_array($name, $only, true))) {
                continue;
            }
            self::flatten($name, $value, $fields);
        }
        $ip = $request->getAttribute('client_ip') ?? $request->getServerParams()['REMOTE_ADDR'] ?? 'unknown';

        return new self($form, $fields, $userId !== null ? "user:{$userId}" : 'ip:' . (is_string($ip) ? $ip : 'unknown'));
    }

    /**
     * Every field's text, one after the other.
     */
    public function text(): string
    {
        return implode("\n", $this->fields);
    }

    /**
     * The text as the same message reads however it is typed: lower case,
     * one space between words, invisible characters (such as zero-width
     * spaces, which hide a word from a filter) removed.
     */
    public function normalized(): string
    {
        $text = (string) preg_replace('/\p{Cf}+/u', '', $this->text());
        $text = (string) preg_replace('/\s+/u', ' ', mb_strtolower($text, 'UTF-8'));

        return trim($text);
    }

    /**
     * @param array<string, string> $fields
     */
    private static function flatten(string $name, mixed $value, array &$fields, int $depth = 0): void
    {
        if (is_string($value)) {
            $fields[$name] = $value;
        } elseif (is_array($value) && $depth < 5) {
            foreach ($value as $key => $item) {
                self::flatten("{$name}[{$key}]", $item, $fields, $depth + 1);
            }
        }
    }
}
