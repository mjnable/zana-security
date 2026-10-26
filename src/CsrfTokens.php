<?php

declare(strict_types=1);

namespace Zana\Security;

use Closure;
use Psr\SimpleCache\CacheInterface;

/**
 * Stateless CSRF tokens, signed with the TokenSigner, so forms are protected
 * without sessions or cookies. A token names its form, carries a random
 * nonce and expires. With a PSR-16 cache and $singleUse, a token is accepted
 * once.
 *
 *     <input type="hidden" name="_token" value="<?= $csrf->issue('contact') ?>">
 *     <input type="hidden" name="_form" value="contact">
 */
final readonly class CsrfTokens
{
    public const string FIELD = '_token';
    public const string FORM_FIELD = '_form';
    public const string HEADER = 'X-CSRF-Token';
    public const string DEFAULT_FORM = 'default';

    private const string SUBJECT_PREFIX = 'csrf:';

    /** @var Closure(): int */
    private Closure $now;

    /**
     * @param int $minimumAge Anti-spam: a form posted sooner after its token was issued looks automated (0 disables)
     * @param string|null $honeypot Anti-spam: a hidden field people never fill in; csrf_field() prints it
     * @param (Closure(): int)|null $clock
     */
    public function __construct(
        private TokenSigner $signer,
        private ?CacheInterface $cache = null,
        private int $lifetime = 7200,
        private bool $singleUse = false,
        public int $minimumAge = 0,
        public ?string $honeypot = null,
        ?Closure $clock = null,
    ) {
        if ($singleUse && $cache === null) {
            throw new SecurityException('Single-use CSRF tokens need a PSR-16 cache.');
        }
        $this->now = $clock ?? static fn (): int => time();
    }

    /**
     * Whether a valid token was issued less than minimumAge seconds ago.
     */
    public function isTooFresh(string $token): bool
    {
        if ($this->minimumAge <= 0) {
            return false;
        }
        try {
            $issuedAt = $this->signer->verify($token)->issuedAt->getTimestamp();
        } catch (InvalidTokenException) {
            return false;
        }

        return ($this->now)() - $issuedAt < $this->minimumAge;
    }

    public function issue(string $form = self::DEFAULT_FORM): string
    {
        return $this->signer->issue(self::SUBJECT_PREFIX . $form, $this->lifetime, ['nonce' => bin2hex(random_bytes(16))]);
    }

    public function verify(string $token, string $form = self::DEFAULT_FORM): bool
    {
        try {
            $claims = $this->signer->verify($token);
        } catch (InvalidTokenException) {
            return false;
        }

        $nonce = $claims->claim('nonce');
        if ($claims->subject !== self::SUBJECT_PREFIX . $form || !is_string($nonce)) {
            return false;
        }

        if ($this->singleUse && $this->cache !== null) {
            $key = 'zana.csrf.' . hash('xxh128', $nonce);
            if ($this->cache->has($key)) {
                return false;
            }
            $this->cache->set($key, true, $this->lifetime);
        }

        return true;
    }
}
