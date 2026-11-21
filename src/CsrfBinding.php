<?php

declare(strict_types=1);

namespace Zana\Security;

use Closure;
use Zana\Session\SessionInterface;

/**
 * Ties CSRF tokens to the visitor's session (2.28), when
 * security.csrf.bind_to_session is on: CsrfTokens are stateless, so without
 * it one visitor's token passes for another's.
 *
 * A visitor who already has a session gets tokens that carry a value derived
 * from a random seed kept in that session, and a request that has a session
 * is accepted only with a token carrying its seed: another visitor's token,
 * or one printed before the session existed, is refused (the form is shown
 * again). A visitor without a session keeps stateless tokens, so no session,
 * and no cookie, is started for a form, and forms on cached public pages
 * still work for visitors without one.
 *
 * CsrfMiddleware sets the session for the request it handles, so the pages
 * that show the forms go through it too (it lets GET requests through).
 * A singleton, as the view helpers that print tokens are: the session is
 * set for one request and put back after it, also in a long-running worker.
 */
final class CsrfBinding
{
    public const string SEED_KEY = '_security.csrf_seed';

    private ?SessionInterface $session = null;

    public function __construct(private readonly bool $enabled = false)
    {
    }

    public function enabled(): bool
    {
        return $this->enabled;
    }

    /**
     * Run $next with the request's session as the one tokens are tied to.
     *
     * @template T
     * @param Closure(): T $next
     * @return T
     */
    public function during(?SessionInterface $session, Closure $next): mixed
    {
        $previous = $this->session;
        $this->session = $this->enabled ? $session : null;
        try {
            return $next();
        } finally {
            $this->session = $previous;
        }
    }

    /**
     * The binding a token issued now carries: null without binding or without an existing session.
     */
    public function forIssue(): ?string
    {
        return $this->current();
    }

    /**
     * The binding a token must carry to be accepted now, or null when any valid token is: without binding, or
     * without an existing session. A session that has no seed yet gets one, so a token from before it, or from
     * another visitor, is refused.
     */
    public function expected(): ?string
    {
        return $this->current();
    }

    private function current(): ?string
    {
        $session = $this->session;
        if ($session === null) {
            return null;
        }
        $seed = $session->get(self::SEED_KEY);
        if (is_string($seed) && strlen($seed) === 64) {
            return self::bind($seed);   // also while a sign-in regenerates the id, which keeps the data
        }
        if ($session->id() === null) {
            return null;   // no session yet: none is started for a form
        }
        $seed = bin2hex(random_bytes(32));
        $session->set(self::SEED_KEY, $seed);

        return self::bind($seed);
    }

    /**
     * Tokens can be read by whoever holds them: they carry a hash of the seed, never the seed.
     */
    private static function bind(string $seed): string
    {
        return substr(hash('sha256', 'zana.csrf.bind:' . $seed), 0, 32);
    }
}
