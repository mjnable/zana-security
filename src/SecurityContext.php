<?php

declare(strict_types=1);

namespace Zana\Security;

use Zana\Http\Exception\UnauthorizedHttpException;

/**
 * The user of the current request. Scoped: one per request scope.
 */
final class SecurityContext
{
    private ?UserInterface $user = null;

    public function user(): ?UserInterface
    {
        return $this->user;
    }

    public function isAuthenticated(): bool
    {
        return $this->user !== null;
    }

    public function setUser(?UserInterface $user): void
    {
        $this->user = $user;
    }

    /**
     * @throws UnauthorizedHttpException When nobody is authenticated
     */
    public function requireUser(): UserInterface
    {
        return $this->user ?? throw new UnauthorizedHttpException(headers: ['WWW-Authenticate' => 'Bearer']);
    }
}
