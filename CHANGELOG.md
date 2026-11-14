# Changelog

All Zana packages share one version number and are released together. A release that did
not change this package is not listed.

## 2.22.0 — Unreleased

### Added

- `Inspection\RouteAccess`: who may reach one route, as its declarations and middleware say: public with its reason,
  a Zana access rule and whether `AuthorizationMiddleware` enforces it, the application's declared sign-in middleware,
  session sign-in, CSRF protection and the enforced rate limit; `needsUser()`, `claimsUser()` and `declared()` (FE-68). The security
  rules of `check` and the attacks of mj-zana/testing read it, so they judge every route alike.

## 2.21.0 — 2026-11-14

### Security

- `check` reports, for every route (FE-68, ADR-033), as errors with `security.strict: true` and warnings otherwise:
  - `security.route_access`: the route does not say who may reach it: `#[RequiresAuthentication]`,
    `#[RequiresPermission]`, or `#[PublicRoute(reason: '…')]` (mj-zana/routing 2.21);
  - `security.access_unenforced`: it requires a user, but `AuthorizationMiddleware` is not on the route, so anyone
    reaches it. Authentication middleware alone does not count: it lets anonymous requests through;
  - `security.global_middleware`: `AuthorizationMiddleware` or `RateLimitMiddleware` in `http.middleware`, where it runs
    before routing and enforces nothing;
  - `security.csrf`: a route that changes data with session sign-in, and no `CsrfMiddleware` or `#[WithoutCsrf]`.
- An application's own sign-in middleware counts as needing a user when it is declared in `security.access_middleware`,
  with the reason it refuses anonymous visitors: `[App\Web\SignedIn::class => 'Sends visitors without an API session to
  sign in']` (ADR-033 amendment). It counts only on the routes it runs on as route middleware, never in
  `http.middleware`, and never as a permission check: `#[RequiresPermission]` still needs `AuthorizationMiddleware`.
  `check` lists the routes that rely on it (`security.application_access`, info), warns when it runs on none, and
  refuses (`security.access_middleware`) a declaration without a reason, a class that is not a middleware, or Zana's
  own middleware, none of which refuses anonymous visitors by itself.
- `security.rate_limit`, always a warning: a public route that changes data without `#[RateLimit]` and
  `RateLimitMiddleware`.
- Requires mj-zana/core 2.21, and mj-zana/routing 2.21 or later when it is installed (`conflict`).

## 2.20.0 — 2026-11-14

### Security

- `DatabaseRoleAssignmentStore` compares a scope by type and id, not as one `type:id` string, as the in-memory store
  already did (S32).
- `TwoFactorStateSwapInterface`, optional for user providers: with it, a second-factor code is accepted only if the
  stored state is still the one it was checked against, so two sign-ins at the same moment cannot give back a used
  recovery code or count one TOTP code twice (S14). Without it, behaviour is unchanged.
- `CsrfMiddleware` compares the port of an `Origin` that names one, so another service on the same host is another site
  (S16). Browsers leave default ports out, so sites behind a proxy are not affected.

## 2.19.2 — 2026-11-07

### Security

- `CsrfTokens::isBearerToken()` refuses any subject with a colon, such as a back-office preview link's.

## 2.19.1 — 2026-11-07

### Security

- A stored second factor that cannot be opened, because `security.two_factor.key` changed or the state was
  damaged, now counts as a second factor that no code passes. Before, it counted as none, and the password alone
  signed in. `TwoFactorFailed` has a new reason, `unreadable`.
- `SessionLogin` stores a fingerprint of the password hash in the session, and `SessionAuthenticationMiddleware`
  signs out a session from before a password change. Sessions from 2.19.0 and earlier have no fingerprint, so
  everyone signs in again once after upgrading.
- `CsrfMiddleware` skips its checks only for a valid bearer token signed by the application. Any other
  `Authorization` header is checked like a request without one, so it no longer bypasses the honeypot and the time
  trap.
- The sign-in limit per address counts failed attempts only, so a successful sign-in no longer resets it, and it
  applies only when an address is given, so callers that pass none no longer share one limit.
- Added `RateLimiter::peek()` and `CsrfTokens::isBearerToken()`.

## 2.17.0 — 2026-11-06

### Added

- Roles in a scope (FE-57, ADR-032):
  - `Scope` and `RoleAssignmentStoreInterface`, with `DatabaseRoleAssignmentStore` (with
    mj-zana/database, `security.role_assignments: database`), `RoleAssignmentsMigration` and
    `InMemoryRoleAssignmentStore`;
  - `RoleAssignments` (scoped) and its events, `RoleAssigned` and `RoleRevoked`, which name who made
    the change.
- The `Authorizer` counts the roles assigned everywhere, and those in the subject's scope and its
  parents:
  - the subject is a `Scope` or `HasAuthorizationScope`;
  - parents come from a registered `ScopeHierarchyInterface`;
  - `rolesOf()` and `scopesOf()` are public.
- `#[RequiresPermission(permission, scope:, parameter:)]` checks the permission in the scope named by
  a route parameter.
- The `security.role_assignments` check.

### Changed

- `mj-zana/database` is an optional dependency (`suggest`); without a store, nothing changes.

## 2.16.0 — 2026-11-06

### Added

- Second factors (FE-56, ADR-031):
  - `Totp` (RFC 6238) and `TwoFactor`, which enrols, confirms, verifies and disables second factors,
    with recovery codes and "remember this device" tokens;
  - `TwoFactorUserProviderInterface`, whose state is sealed with libsodium under
    `security.two_factor.key`;
  - the `security.two_factor_key` check.
- `SessionLogin::start()`, `completeSecondFactor()` and `hasPendingSecondFactor()`, with
  `LoginResult`. A user with a second factor is never signed in by the password alone; `attempt()`
  then returns null and leaves the sign-in pending.
- `OneTimeCodes`: numeric codes for a subject and a purpose. They are stored as HMACs, expire, work
  once, and limit attempts and issuing.
- Events: `TwoFactorEnabled`, `TwoFactorDisabled`, `TwoFactorFailed` and `RecoveryCodeUsed`.
  `SignInSucceeded::$method` names the second step.

### Changed

- Requires `mj-zana/core` ^2.11, for the check.

## 2.15.0 — 2026-11-06

### Added

- Security events (FE-58): with an event dispatcher, `SessionLogin` dispatches `SignInSucceeded`,
  `SignInFailed` (`invalid_credentials` or `throttled`) and `SignedOut`. `PasswordResetTokens`
  dispatches `PasswordResetRequested` and `PasswordResetTokenUsed`. All of them implement
  `SecurityEvent`, and mj-zana/audit records them in its security audit log.
- `SessionLogin::logout()` takes the client address, for the `SignedOut` event.

### Changed

- Requires `psr/event-dispatcher` ^1.0. The provider gives the dispatcher to `SessionLogin` and
  `PasswordResetTokens` when one is registered; without one, nothing changes.

## 2.9.0 — 2026-11-01

### Fixed

- Without a PSR-16 cache, `RateLimiter` and `PasswordResetTokens` can be created and fail only when
  they are used, so `check` and `doctor` no longer report the rate limiter in applications that do
  not rate-limit (ADR-024).

## 2.4.0 — 2026-10-26

### Changed

- `PasswordResetTokens` is registered scoped, so the user provider may be scoped like other
  repositories; a singleton that receives it now fails the build, naming both (FE-40).
- Factory registrations declare the services they resolve with `uses()`.
- Requires `mj-zana/core` ^2.4.

## 2.3.0 — 2026-10-26

### Changed

- Tests and tooling (`tests/`, `phpunit.xml.dist`, `phpstan.neon.dist`) are no longer in Composer
  archives, so they stay out of production `vendor/` folders (FE-17).

## 2.2.0 — 2026-10-26

### Added

- Rate limiting: `RateLimiter` (fixed and sliding windows), `#[RateLimit]` and
  `RateLimitMiddleware`, with `RateLimit-*` headers and 429 responses (FE-10).
- Anti-spam for public forms: a honeypot field and a minimum form age in `CsrfTokens`
  (`security.csrf.honeypot`, `security.csrf.minimum_age`), and `security.csrf.spam_redirect`
  (FE-22).
- Session sign-in for a back office: `SessionLogin` with attempt limits,
  `SessionAuthenticationMiddleware` with a redirect to `security.login.path`,
  `PasswordUserProviderInterface`, `PasswordUpgraderInterface` and `PasswordResetTokens` (FE-28).
  The session classes are registered when `mj-zana/session` is installed.

## 2.1.0 — 2026-10-26

### Added

- Stateless CSRF protection: `CsrfTokens`, `CsrfMiddleware` and `#[WithoutCsrf]` (FE-05).

## 2.0.0 — 2026-10-26

The final 2.0 release. No changes since 2.0.0-rc.1.

## 2.0.0-rc.1 — 2026-10-25

### Security

- `PasswordHasher`: bcrypt reads only the first 72 bytes of a password and stops at a NUL byte, so
  two passwords sharing a 72-byte prefix verified against each other. For bcrypt, such passwords are
  now pre-hashed with SHA-384. **bcrypt hashes of such passwords made by a beta no longer verify;**
  Argon2id hashes are unaffected.

## 2.0.0-alpha.3 — 2026-10-24

First release of the 2.0 line. Password hashing, signed bearer tokens, request authentication, and authorization by roles, permissions and policies. Requires PHP 8.5 or later.

Documentation: [the security guide](https://github.com/mjnable/zana-docs/blob/main/guides/security.md).
