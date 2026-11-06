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

## New in 2.15: security events

With an event dispatcher (`mj-zana/events`), `SessionLogin` dispatches
`SignInSucceeded`, `SignInFailed` (wrong credentials, or throttled) and
`SignedOut`. `PasswordResetTokens` dispatches `PasswordResetRequested` and
`PasswordResetTokenUsed`. They all implement `SecurityEvent`.
`mj-zana/audit` records them in its security audit log. You can also listen
to them yourself, for example to alert on repeated failures:

```php
$listeners->listen(SignInFailed::class, AlertOnRepeatedFailures::class);
```

A failed sign-in carries the login that was typed and the client address,
never the password.

## New in 2.16: second factors and one-time codes

**TOTP** (RFC 6238, as authenticator apps compute it), with recovery codes.
Make your user provider implement `TwoFactorUserProviderInterface`. It
stores one opaque, encrypted string per user, in a nullable text column.
Then set `security.two_factor.key`:

```
APP_SECURITY__TWO_FACTOR__KEY=   # php -r "echo bin2hex(random_bytes(32));"
```

```php
$enrolment = $twoFactor->enrol($user);       // show $enrolment->uri as a QR code; give the recovery codes
$twoFactor->confirm($user, $codeFromTheApp); // the second factor is now on
```

`SessionLogin` then asks for a code after the password:

```php
$result = $login->start($email, $password, $clientIp, $request->getCookieParams()['device'] ?? null);
if ($result->needsSecondFactor()) { /* show the code form */ }
$result = $login->completeSecondFactor($code, $clientIp, remember: true);
// $result->deviceToken: a "remember this device" cookie (security.two_factor.remember_days)
```

- **No password-only sign-in:** a user with a second factor is never signed
  in by the password alone, not even through `attempt()`. The pending
  sign-in lasts 5 minutes.
- **Codes:**
  - a code is accepted 30 seconds early or late, and only once;
  - recovery codes are stored as HMACs, each works once, and they can be
    regenerated;
  - attempts are limited per user (`security.two_factor.max_attempts` per
    `security.two_factor.window`).
- **Encryption:** the state is sealed with libsodium under
  `security.two_factor.key`, which is separate from `security.secret`.
  Changing the key locks out every user with a second factor, so keep it.
- **Events:** `TwoFactorEnabled`, `TwoFactorDisabled`, `TwoFactorFailed` and
  `RecoveryCodeUsed`. `SignInSucceeded` names the method, for example
  `session+two_factor`.
- **Check:** `security.two_factor_key` reports a missing or short key when
  your user provider holds second factors.

**One-time codes** confirm a phone number or an email address. Sending them
by SMS or WhatsApp is up to you:

```php
$code = $codes->issue('+243810000000', 'phone.confirm');
$codes->verify('+243810000000', 'phone.confirm', $typed);   // true once
```

A code expires (10 minutes by default) and works once. It is refused after 5
wrong tries, and issuing is rate-limited (`security.one_time_codes.max_issues`
per `security.one_time_codes.window`). Codes are kept in the PSR-16 cache.

## New in 2.17: roles in an organization or at an event

A user can be the owner of one organization, a box-office agent at another,
and a scanner at one event only. Give roles in a scope with
`RoleAssignments`:

```php
$roles->assign($userId, 'owner', new Scope('organization', $orgId));
$roles->assign($userId, 'scanner', new Scope('event', $eventId));
$roles->assign($userId, 'admin');                          // everywhere
```

The `Authorizer` counts the roles given in the subject's scope, and in the
scopes above it, beside the user's own `roles()`:

```php
$authorizer->can($user, 'tickets.scan', new Scope('event', $eventId));
$authorizer->can($user, 'events.publish', $event);   // $event implements HasAuthorizationScope
```

```php
#[RequiresPermission('tickets.scan', scope: 'event')]   // the id from the route parameter {eventId}
```

- **Storage:** set `security.role_assignments` to `"database"` (with
  `mj-zana/database`). Add a migration that returns
  `new RoleAssignmentsMigration()`. Or register your own
  `RoleAssignmentStoreInterface`, as a singleton.
- **Parents:** register a `ScopeHierarchyInterface` to say that an event
  belongs to an organization, so the organization's owner has their roles
  at its events. Roles never flow from an event up to its organization.
- **Policies** still decide first; the `Scope` is their subject.
- **Events:** `RoleAssigned` and `RoleRevoked`, with who made the change.
  `mj-zana/audit` records them.
- **Check:** `security.role_assignments` reports a store that cannot be read.
- **Opt-in:** without the setting or a store, nothing changes.
- **Your queries:** filtering by organization stays in your repositories.

## License

MIT — see [LICENSE](LICENSE).
