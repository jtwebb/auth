# Security

## Reporting a vulnerability

Please do **not** open public issues for security vulnerabilities.

- Email: `security@jtwebb.dev`
- Include: affected version, impact, reproduction steps, and any suggested fix

## Design goals

- **No plaintext secrets stored** (passwords, session tokens, backup codes)
- **Secure defaults** (httpOnly cookies, strict rpId/origin checks, single-use challenges)
- **Explicit policy knobs** so apps can tune security vs UX

## What this library does (and does not) do

- **Does**: password hashing (Argon2id), WebAuthn verification, session token generation + hashing, backup code hashing
- **Does not**: ship a DB adapter (you implement storage), run rate limiting for you (but provides hooks/events)

## Recommended deployment requirements

- **HTTPS only** (passkeys require secure context; cookies should always be `Secure`)
- **Set CSP** and other standard headers
- **Use a secrets manager** for: `PASSWORD_PEPPER`, `SESSION_TOKEN_HMAC_SECRET`, `BACKUP_CODE_HMAC_SECRET`
- **Add rate limiting** on auth endpoints (especially password login and passkey start endpoints)

