<?php

declare(strict_types=1);

namespace Zana\Security\Tests;

use PHPUnit\Framework\TestCase;
use Zana\Security\InvalidTokenException;
use Zana\Security\PasswordHasher;
use Zana\Security\SecurityException;
use Zana\Security\TokenSigner;

final class PasswordAndTokenTest extends TestCase
{
    private const string SECRET = 'a-test-secret-that-is-long-enough!!';

    private int $now = 1_800_000_000;

    public function testHashingAndVerifying(): void
    {
        $hasher = new PasswordHasher(['memory_cost' => 8192, 'time_cost' => 1]);
        $hash = $hasher->hash('correct horse');

        $this->assertSame(PASSWORD_ARGON2ID, $hasher->algorithm());
        $this->assertStringStartsWith('$argon2id$', $hash);
        $this->assertTrue($hasher->verify('correct horse', $hash));
        $this->assertFalse($hasher->verify('wrong horse', $hash));
        $this->assertFalse($hasher->needsRehash($hash));
        $this->assertTrue(new PasswordHasher(['memory_cost' => 16384, 'time_cost' => 1])->needsRehash($hash), 'other options');

        $bcrypt = new PasswordHasher(['cost' => 4], PASSWORD_BCRYPT);
        $this->assertTrue($bcrypt->needsRehash($hash), 'other algorithm');
        $this->assertTrue($bcrypt->verify('correct horse', $bcrypt->hash('correct horse')));
    }

    public function testBcryptChecksEveryByte(): void
    {
        $bcrypt = new PasswordHasher(['cost' => 4], PASSWORD_BCRYPT);
        $prefix = str_repeat('a', 72);
        $hash = $bcrypt->hash($prefix . 'SECRET-ONE');

        $this->assertTrue($bcrypt->verify($prefix . 'SECRET-ONE', $hash));
        $this->assertFalse($bcrypt->verify($prefix . 'SECRET-TWO', $hash), 'past 72 bytes');
        $this->assertFalse($bcrypt->verify($prefix, $hash));

        $nul = $bcrypt->hash("abc\0def");
        $this->assertTrue($bcrypt->verify("abc\0def", $nul));
        $this->assertFalse($bcrypt->verify("abc\0xyz", $nul), 'past a NUL byte');

        $argon = new PasswordHasher(['memory_cost' => 8192, 'time_cost' => 1]);
        $this->assertTrue($argon->verify($prefix . 'SECRET-ONE', $hash), 'bcrypt hashes verify before a rehash');
        $this->assertFalse($argon->verify($prefix . 'SECRET-TWO', $hash));
    }

    public function testLongPasswordsAreRejected(): void
    {
        $hasher = new PasswordHasher(['memory_cost' => 8192, 'time_cost' => 1]);
        $hash = $hasher->hash(str_repeat('a', PasswordHasher::MAX_LENGTH));

        $this->assertFalse($hasher->verify(str_repeat('a', PasswordHasher::MAX_LENGTH + 1), $hash));

        $this->expectException(SecurityException::class);
        $hasher->hash(str_repeat('a', PasswordHasher::MAX_LENGTH + 1));
    }

    public function testTokensRoundTrip(): void
    {
        $signer = $this->signer();
        $token = $signer->issue('ada', 3600, ['clinic' => 'north', 'scopes' => ['read']]);

        $this->assertMatchesRegularExpression('/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/', $token);
        $claims = $signer->verify($token);
        $this->assertSame('ada', $claims->subject);
        $this->assertSame($this->now, $claims->issuedAt->getTimestamp());
        $this->assertSame($this->now + 3600, $claims->expiresAt->getTimestamp());
        $this->assertSame('north', $claims->claim('clinic'));
        $this->assertSame(['read'], $claims->claim('scopes'));
        $this->assertSame('none', $claims->claim('missing', 'none'));
        $this->assertSame([], $signer->verify($signer->issue('ada', 60))->claims);
    }

    public function testRejectedTokens(): void
    {
        $signer = $this->signer();
        $token = $signer->issue('ada', 60);
        [$payload, $signature] = explode('.', $token);
        $forged = rtrim(strtr(base64_encode('{"sub":"admin","iat":1,"exp":9999999999,"claims":{}}'), '+/', '-_'), '=');

        $this->assertRejected(InvalidTokenException::SIGNATURE, $signer, "{$forged}.{$signature}");
        $this->assertRejected(InvalidTokenException::SIGNATURE, $signer, $payload . '.' . strrev($signature));
        $this->assertRejected(InvalidTokenException::SIGNATURE, new TokenSigner(str_repeat('x', 32)), $token);
        foreach (['', 'abc', 'a.b.c', '.sig', 'payload.'] as $malformed) {
            $this->assertRejected(InvalidTokenException::MALFORMED, $signer, $malformed);
        }

        $this->now += 60;
        $this->assertRejected(InvalidTokenException::EXPIRED, $signer, $token);
    }

    public function testASignedButMalformedPayloadIsRejected(): void
    {
        $signer = $this->signer();
        $payload = rtrim(strtr(base64_encode('{"sub":42}'), '+/', '-_'), '=');
        $signature = rtrim(strtr(base64_encode(hash_hmac('sha256', $payload, self::SECRET, true)), '+/', '-_'), '=');

        $this->assertRejected(InvalidTokenException::MALFORMED, $signer, "{$payload}.{$signature}");
    }

    public function testSignerArguments(): void
    {
        foreach ([
            static fn () => new TokenSigner('too short'),
            fn () => $this->signer()->issue('', 60),
            fn () => $this->signer()->issue('ada', 0),
            fn () => $this->signer()->issue('ada', 60, ['bad' => NAN]),
        ] as $invalid) {
            try {
                $invalid();
                $this->fail('Invalid signer use must be rejected.');
            } catch (SecurityException $e) {
                $this->assertNotInstanceOf(InvalidTokenException::class, $e);
            }
        }
    }

    private function signer(): TokenSigner
    {
        return new TokenSigner(self::SECRET, fn (): int => $this->now);
    }

    private function assertRejected(string $reason, TokenSigner $signer, string $token): void
    {
        try {
            $signer->verify($token);
            $this->fail("The token \"{$token}\" must be rejected.");
        } catch (InvalidTokenException $e) {
            $this->assertSame($reason, $e->reason, "for \"{$token}\"");
        }
    }
}
