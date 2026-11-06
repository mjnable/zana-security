<?php

declare(strict_types=1);

namespace Zana\Security\Internal;

/**
 * RFC 4648 base32, without padding: the encoding of TOTP secrets in
 * authenticator apps.
 *
 * @internal
 */
final class Base32
{
    private const string ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    public static function encode(string $bytes): string
    {
        $bits = '';
        foreach (str_split($bytes) as $byte) {
            $bits .= str_pad(decbin(ord($byte)), 8, '0', STR_PAD_LEFT);
        }
        $out = '';
        foreach (str_split($bits, 5) as $chunk) {
            $out .= self::ALPHABET[(int) bindec(str_pad($chunk, 5, '0'))];
        }

        return $bytes === '' ? '' : $out;
    }

    public static function decode(string $text): string
    {
        $text = strtoupper(str_replace(['=', ' ', '-'], '', $text));
        $bits = '';
        foreach (str_split($text) as $char) {
            $value = strpos(self::ALPHABET, $char);
            if ($value === false) {
                throw new \InvalidArgumentException('The secret is not valid base32.');
            }
            $bits .= str_pad(decbin($value), 5, '0', STR_PAD_LEFT);
        }
        $out = '';
        foreach (str_split($bits, 8) as $chunk) {
            if (strlen($chunk) === 8) {
                $out .= chr(((int) bindec($chunk)) & 0xFF);
            }
        }

        return $text === '' ? '' : $out;
    }
}
