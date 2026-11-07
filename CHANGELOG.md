# Changelog

All Zana packages share one version number and are released together. A release that did
not change this package is not listed.

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
