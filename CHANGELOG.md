# Changelog

All Zana packages share one version number and are released together. A release that did
not change this package is not listed.

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
