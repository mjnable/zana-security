# Zana Security

Password hashing, signed bearer tokens, request authentication, and
authorization by roles, permissions and policies. Requires PHP 8.5 or later.

```
composer require mj-zana/security
```

## Setup

Register `SecurityServiceProvider` after `HttpServiceProvider` (and
`RoutingServiceProvider`). Then implement and register
`UserProviderInterface`, whose users implement `UserInterface`.

```php
// config/security.php
return [
    'secret' => $_ENV['APP_SECRET'],                  // at least 32 bytes
    'password_options' => ['memory_cost' => 65536],   // password_hash() options
    'roles' => [
        'viewer' => ['reports.view'],
        'clinician' => ['measurements.create', 'measurements.edit'],
        'admin' => ['*'],
    ],
    'hierarchy' => ['clinician' => ['viewer']],
    'policies' => [MeasurementPolicy::class],
];

// config/http.php
return ['middleware' => [AuthenticationMiddleware::class]];
```

## Passwords and tokens

```php
$hash = $hasher->hash($plain);                         // Argon2id, or bcrypt without it
if ($hasher->verify($plain, $hash) && $hasher->needsRehash($hash)) { /* store $hasher->hash($plain) */ }

$token = $signer->issue($user->identifier(), 3600, ['clinic' => 'north']);
$claims = $signer->verify($token);                     // InvalidTokenException: malformed, signature or expired
```

- **Passwords:** longer than 4,096 bytes are rejected. For bcrypt, passwords
  over 72 bytes or containing a NUL byte are pre-hashed with SHA-384, so every
  byte counts.
- **Tokens:** a token is `base64url(JSON) . "." . base64url(HMAC-SHA256)`.
  It is signed, not encrypted, so keep secrets out of the claims.

## Authentication

`AuthenticationMiddleware` reads `Authorization: Bearer <token>`:

- **Valid token:** it loads the user, sets it on the scoped
  `SecurityContext` and as the request attribute `user`.
- **No header:** the request continues anonymously.
- **Bad scheme, bad token or unknown user:** the request gets a 401 with
  `WWW-Authenticate: Bearer`.

## Authorization

```php
#[RequiresAuthentication]
final class ProfileController { /* ... */ }

#[RequiresPermission('reports.view')]
final class ReportController
{
    #[RequiresPermission('reports.export')]            // both permissions are required
    public function export(): Response { /* ... */ }
}

$router->group('/api', $routes, [AuthorizationMiddleware::class]);
```

`AuthorizationMiddleware` checks these attributes on the matched handler,
so add it as route middleware. A missing user gets a 401 and a missing
permission a 403.

`Authorizer::can($user, $permission, $subject)` decides in two steps:

1. **Policies:** policies that support the permission vote in order, and the
   first `true` or `false` wins.
2. **Roles:** if no policy decides, the user's roles (with inherited ones)
   are checked, and `*` grants everything.

`authorize()` throws a 403 instead of returning false.

## New in 2.1: CSRF protection

Stateless, without sessions or cookies. Add `CsrfMiddleware` to the routes
that receive forms, and print the token in each form:

```php
<input type="hidden" name="_token" value="<?= $csrf->issue('contact') ?>">
<input type="hidden" name="_form" value="contact">
```

With `mj-zana/view`, `csrf_field('contact')` prints both fields.
- **Checks:** cross-site `Sec-Fetch-Site` and `Origin` headers are refused,
  and the token must match its form and not be expired.
- **Exemptions:** requests with an `Authorization` header, and handlers
  marked `#[WithoutCsrf]`, are not checked.
- **Configuration:** `security.csrf.lifetime` (default 7200 s), and
  `security.csrf.single_use`, which needs a PSR-16 cache.

## License

MIT — see [LICENSE](LICENSE).
