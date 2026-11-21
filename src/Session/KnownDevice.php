<?php

declare(strict_types=1);

namespace Zana\Security\Session;

/**
 * The "known device" cookie of one request (2.31): what the browser sent,
 * which SessionLogin reads when start() is not given one, and the token a
 * sign-in issued, which KnownDeviceMiddleware sets as the cookie. Scoped, as
 * SessionLogin is.
 */
final class KnownDevice
{
    private ?string $presented = null;

    private ?string $issued = null;

    public function present(#[\SensitiveParameter] ?string $token): void
    {
        $this->presented = $token;   // SessionLogin reads an empty one as none
    }

    public function presented(): ?string
    {
        return $this->presented;
    }

    public function issue(#[\SensitiveParameter] string $token): void
    {
        $this->issued = $token;
    }

    public function issued(): ?string
    {
        return $this->issued;
    }
}
