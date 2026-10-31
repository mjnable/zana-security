<?php

declare(strict_types=1);

namespace Zana\Security\Tests;

use PHPUnit\Framework\TestCase;
use Zana\Core\Application;
use Zana\Security\RateLimit\RateLimiter;
use Zana\Security\SecurityException;
use Zana\Security\SecurityServiceProvider;

/**
 * ADR-024: without a PSR-16 cache, the rate limiter can still be created (as
 * check and doctor do for every singleton) and fails only when it is used.
 */
final class WithoutCacheTest extends TestCase
{
    public function testTheRateLimiterFailsOnlyWhenUsed(): void
    {
        $limiter = Application::configure(sys_get_temp_dir() . '/zana-security-no-cache')
            ->withEnvironment('testing')
            ->withProviders(SecurityServiceProvider::class)
            ->withConfiguration(['security.secret' => str_repeat('s', 40)])
            ->build()
            ->container()
            ->get(RateLimiter::class);
        $this->assertInstanceOf(RateLimiter::class, $limiter);

        $this->expectException(SecurityException::class);
        $this->expectExceptionMessage('Rate limiting need a PSR-16 cache: register mj-zana/cache');
        $limiter->attempt('login:198.51.100.1', 5, 60);
    }
}
