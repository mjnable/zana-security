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
$passed = $mode === 'limit' ? $limiter->attempt('login|ip:203.0.113.9', 5, 900)->allowed : $csrf->verify($token);
echo $passed ? '[Y]' : '[N]';
