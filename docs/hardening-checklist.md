# Hardening checklist (production)

This doc is intentionally practical: **what to configure**, **how to generate secrets**, **how to run rate limiting in multi-instance deployments**, and **what to monitor**.

## 1) Secrets: generate, store, rotate

This library relies on application-provided secrets for hashing/encryption. Treat them like production credentials:

- Store in a **secrets manager/KMS** (AWS Secrets Manager, GCP Secret Manager, Vault, etc.)
- Rotate with a rollout plan (keep old keys available where needed)
- Never log or commit them

### Recommended secrets

- **`SESSION_TOKEN_HMAC_SECRET`**: HMAC for session tokens (recommended)
- **`BACKUP_CODE_HMAC_SECRET`**: HMAC for backup codes (recommended)
- **`PASSWORD_PEPPER`**: mixed into password hashing (recommended; rotating invalidates all stored passwords)
- **`TOTP_ENCRYPTION_KEY_*`**: encrypts TOTP secrets at rest (required if you enable TOTP)
- **`PASSWORD_RESET_TOKEN_HMAC_SECRET`**: HMAC for password reset tokens (recommended)

### Generate secrets

Use 32 bytes (256-bit) random values.

Examples:

```bash
# Base64 (portable)
openssl rand -base64 32

# Hex
openssl rand -hex 32
```

### Rotation guidance

- **HMAC secrets (sessions/backup/reset tokens)**:
  - Best practice is to support a key ring (current + previous) during rotation.
  - If you don’t have a key ring yet, rotate during a planned maintenance window and accept invalidation.

- **TOTP encryption key**:
  - This library supports a key ring for TOTP (`totpEncryptionKey: { primaryKeyId, keys }`).
  - Rotate by deploying with both keys, then later removing the old key after re-enrollment/migration.

## 2) Cookies: names, prefixes, SameSite

Prefer **prefix-hardened** cookies for session transport:

- Use **`__Host-`** prefix when possible:
  - must be `Secure`
  - must be `Path=/`
  - must **not** set `Domain`

Example session cookie:

```ts
sessionCookie: {
  name: '__Host-sid',
  path: '/',
  httpOnly: true,
  secure: true,
  sameSite: 'lax'
}
```

CSRF cookie defaults (double-submit) should usually be:

- `Secure: true`
- `SameSite: Strict`
- `HttpOnly: false` (so browser JS can send it in a header), **or** embed it server-side in forms

## 3) Rate limiting in production (Redis example)

The built-in limiter is in-memory (single instance). In production (multiple instances), enforce limits using a shared store such as **Redis** or at the edge (CDN/WAF).

### Proxy / client IP trust boundary

If you derive client identity from headers like `x-forwarded-for`, ensure your deployment is behind a **trusted proxy/CDN** that overwrites these headers. Otherwise attackers can spoof them and bypass per-client limits.

In the React Router adapter, the safest pattern is:
- Provide a custom `getClientId`, or
- Enable `trustProxyHeaders: true` only when you control the proxy layer.

### Keying strategy (recommended)

Use multiple keys per endpoint to resist distributed attacks:

- **Password login**:
  - per identifier: `auth:pw:ident:<normalizedIdentifier>`
  - per client: `auth:pw:ip:<ip>`
- **Passkey start/finish**:
  - per client: `auth:pk:ip:<ip>`
  - per challenge id (finish): `auth:pk:chal:<challengeId>`
- **TOTP verify**:
  - per client: `auth:totp:ip:<ip>`
  - per pending token: `auth:totp:pending:<pendingToken>`

### Atomic fixed-window counter (Lua)

This is a common Redis pattern: `INCR` + set expiry only on first increment.

```lua
-- KEYS[1] = key
-- ARGV[1] = ttl_ms
local v = redis.call("INCR", KEYS[1])
if v == 1 then
  redis.call("PEXPIRE", KEYS[1], ARGV[1])
end
return v
```

In your app, block when `count > max` and return HTTP 429 with `Retry-After`.

## 4) CSRF: use the adapter helper

For browser apps, keep **both**:

- origin allowlist checks
- double-submit CSRF tokens

In React Router:

- mint token on GET/loader via `auth.csrf.getToken(request)`
- include it in form field `csrfToken` or header `x-csrf-token`

Avoid disabling CSRF checks unless you truly aren’t using cookies (pure token auth) and you understand the risks.

## 5) Monitoring & alerting

Use `onAuthAttempt` to create low-cardinality counters (no secrets).

Suggested alerts:

- Spike in **`password_login` failures** (especially per identifier)
- Spike in **`totp_verify` failures**
- Spike in **`passkey_login_finish` failures**
- Any sustained **`rate_limited`** responses (could indicate attack or broken clients)
- Spike in **`password_reset_invalid`** (token stuffing / replay)

Suggested dashboards:

- Auth attempts by type + success/failure
- Rate-limit blocks by endpoint + key category (ip vs identifier)
- Session revocations (`logout`, `sessions_revoke_all`, `sessions_revoke_other`)

## 6) Operational hygiene

- Terminate TLS at a trusted layer; enforce HTTPS everywhere
- Add standard headers (CSP, HSTS, etc.)
- Consider WAF/edge protections for `/login`, passkey endpoints, and password reset endpoints
- Ensure database operations that must be single-use are **atomic** (challenges, backup codes, reset tokens, session rotation)
