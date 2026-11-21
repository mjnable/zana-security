<?php

declare(strict_types=1);

namespace Zana\Security\Session;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Zana\Http\BasePath;

/**
 * Sets and reads the "known device" cookie for SessionLogin (2.31), so an
 * application gets the 2.28 lockout protection whole by adding this
 * middleware to its sign-in routes, with no change to its controller:
 *
 * - before the handler, the cookie the browser sent is given to SessionLogin,
 *   which lets that browser through the limit on the login from every
 *   address, for the user it names, while others are locked out;
 * - after a sign-in, the new token is set as the cookie: HttpOnly,
 *   SameSite=Lax, Secure on HTTPS, for security.login.known_device_days.
 *
 * The cookie never signs anyone in, and never replaces the password.
 *
 * Put it before SessionMiddleware: the session cookie is then the first
 * Set-Cookie of the response, as tests that carry only the first one expect
 * (found on MMC, whose back-office tests did so).
 */
final readonly class KnownDeviceMiddleware implements MiddlewareInterface
{
    public const string DEFAULT_COOKIE = 'zana_device';

    /** Signed tokens: base64url parts joined by dots. */
    private const string TOKEN = '/^[A-Za-z0-9_\-]+(\.[A-Za-z0-9_\-]+)+$/';

    private const int MAX_LENGTH = 1024;

    public function __construct(
        private KnownDevice $device,
        private string $cookie = self::DEFAULT_COOKIE,
        private int $lifetime = SessionLogin::KNOWN_DEVICE_LIFETIME,
    ) {
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $sent = $request->getCookieParams()[$this->cookie] ?? null;
        // Only what looks like a token reaches the signer; anything else is no cookie at all.
        $this->device->present(is_string($sent) && strlen($sent) <= self::MAX_LENGTH && preg_match(self::TOKEN, $sent) === 1 ? $sent : null);

        $response = $handler->handle($request);

        $issued = $this->device->issued();
        if ($issued === null) {
            return $response;
        }
        $base = $request->getAttribute(BasePath::ATTRIBUTE, '');
        $parts = [
            "{$this->cookie}={$issued}",
            'Path=' . (is_string($base) && $base !== '' ? $base : '/'),
            "Max-Age={$this->lifetime}",
            'HttpOnly',
            'SameSite=Lax',
        ];
        if ($request->getUri()->getScheme() === 'https') {
            $parts[] = 'Secure';
        }

        return $response->withAddedHeader('Set-Cookie', implode('; ', $parts));
    }
}
