<?php

declare(strict_types=1);

namespace Zana\Security\Event;

/**
 * A sign-in, sign-out or password reset (FE-58, 2.15), dispatched through
 * the PSR-14 event dispatcher when one is registered. Listen to this
 * interface for all of them, e.g. mj-zana/audit's security audit log, or to
 * one class, e.g. to alert on repeated failures.
 */
interface SecurityEvent
{
    /**
     * A stable name, such as "security.sign_in".
     */
    public function action(): string;
}
