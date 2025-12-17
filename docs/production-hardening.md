# Production hardening

## Sessions (cookie transport, DB-backed)

- **Cookie**: `httpOnly`, `secure`, `sameSite=lax` (or `strict` if it fits your UX), `path=/`
- **DB storage**: store only `tokenHash` (HMAC-SHA256 recommended)
- **Rotation**: keep `rotateEveryMs` enabled so long-lived cookies don’t become long-lived bearer tokens
- **TTL**: set both absolute and idle TTLs that match your risk tolerance

## CSRF

The React Router adapter performs an **Origin allowlist** check for state-changing requests by default.

- Keep `csrf.enabled=true`
- Set `policy.passkey.origins` (or adapter `csrf.allowedOrigins`) to exact origins

## Passwords

- Argon2id is used with configurable parameters.
- Prefer long passwords over complexity rules.
- Keep a `PASSWORD_PEPPER` secret (rotating it invalidates all stored passwords).

## Passkeys (WebAuthn)

- Set `policy.passkey.rpId` to your domain (e.g. `example.com`)
- Set `policy.passkey.origins` to exact HTTPS origins
- Prefer `userVerification: "preferred"` or `"required"`
- Persist and validate `counter` updates to mitigate replay

## Backup codes

- Only show plaintext codes once.
- Store hashes only (use `backupCodeHashSecret` to mitigate offline guessing).
- Ensure single-use consumption is atomic in your DB.

## Rate limiting & auditing

Implement rate limiting on:
- password login
- passkey login start
- passkey registration start
- backup code redemption

Never log:
- passwords
- session tokens
- backup codes
- passkey assertion/attestation payloads (they can contain identifying info)


