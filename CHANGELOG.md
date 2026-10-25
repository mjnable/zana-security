# Changelog

All Zana packages share one version number and are released together. A release that did
not change this package is not listed.

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
