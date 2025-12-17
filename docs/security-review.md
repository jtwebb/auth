# Security review checklist

## Sessions

- Cookie transport uses **httpOnly + secure + sameSite** and `path=/`
- Session tokens are **high entropy** and stored server-side as **hash only**
- Rotation is enabled (`rotateEveryMs`) and old tokens are revoked atomically
- Absolute + idle expiry are enforced

## CSRF

- Origin allowlist is enabled for state-changing actions
- Allowed origins list is exact and environment-specific

## Passwords

- Argon2id used for password hashing
- Pepper is configured and stored in a secrets manager
- Login errors do not leak user existence (generic “invalid credentials”)

## Passkeys (WebAuthn)

- `rpId` and `origins` are correct and strict (HTTPS only in prod)
- Challenges are single-use and expire
- Credential counter is stored and updated
- No sensitive passkey payloads are logged

## Backup codes

- Plaintext backup codes are displayed once
- Only hashes are stored (HMAC secret recommended)
- Consumption is atomic (single-use)

## Logging & telemetry

- Do not log: passwords, session tokens, backup codes, WebAuthn assertions/attestations
- Rate-limit auth endpoints and add alerting for anomalous traffic


