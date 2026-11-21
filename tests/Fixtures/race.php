<?php

declare(strict_types=1);

// One of ConcurrencyTest's processes: waits for the shared start time, then either one rate-limit attempt ("limit")
// or one single-use CSRF verification ("token") against a FileCache shared with the others. Each kind is raced on its
// own: a rate limit's lock taken first would space the processes out, and hide a race in the token check.
// Prints "[Y]" when it passed, "[N]" when not.

require dirname(__DIR__, 2) . '/vendor/autoload.php';

[, $mode, $directory, $start, $token] = $_SERVER['argv'];
$cache = new Zana\Cache\FileCache($directory);
$limiter = new Zana\Security\RateLimit\RateLimiter($cache);
$csrf = new Zana\Security\CsrfTokens(new Zana\Security\TokenSigner(str_repeat('k', 32)), $cache, singleUse: true);
while (microtime(true) < (float) $start) {
    usleep(200);
}
// 2.29: the same message posted by every process. "spam" judges and claims, as SpamGuardMiddleware does since 2.29;
// "spam-reserve" judges and reserves, as it did before.
$guard = new Zana\Security\Spam\SpamGuard(['contact' => ['duplicate_minutes' => 30, 'duplicate_scope' => 'everyone']], $cache, static fn (string $class): Zana\Security\Spam\SpamRuleInterface => throw new LogicException("No application rule here: {$class}"));
$submission = new Zana\Security\Spam\Submission('contact', ['message' => 'Buy cheap watches today'], '203.0.113.9');
$passed = match ($mode) {
    'limit' => $limiter->attempt('login|ip:203.0.113.9', 5, 900)->allowed,
    'token' => $csrf->verify($token),
    'spam' => !(($verdict = $guard->judge('contact', $submission))->spam || $guard->claim('contact', $submission, $verdict)->spam),
    'spam-reserve' => (static function () use ($guard, $submission): bool {
        if ($guard->judge('contact', $submission)->spam) {
            return false;
        }
        $guard->reserve('contact', $submission);

        return true;
    })(),
    default => throw new InvalidArgumentException("Unknown mode: {$mode}"),
};
echo $passed ? '[Y]' : '[N]';
