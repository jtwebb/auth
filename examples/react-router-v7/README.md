# React Router v7 Framework example (loaders/actions) + Kysely

This folder is a **copy/paste example** meant to drop into a React Router v7 Framework app created with:

```bash
npx create-react-router@latest --template remix-run/react-router-templates/minimal
```

It demonstrates, in **route modules** (loaders/actions) rather than `fetch()` in components:

- Password + passkey registration
- Password + passkey login (discoverable passkey login too)
- 2FA (TOTP) enable/disable, and login with/without 2FA
- Backup codes rotation + using a backup code as a 2FA fallback
- CSRF protection via **Origin checks** (same-origin enforcement)
- A protected page (loader gate) and session rotation header propagation

Everything uses the **Kysely adapter** (`@jtwebb/auth/kysely`).

## How to use (copy/paste)

1. Create a new app:

```bash
npx create-react-router@latest --template remix-run/react-router-templates/minimal
```

2. Copy this folder’s `app/` contents into your app’s `app/` directory:

- `examples/react-router-v7/app/*` → `your-app/app/*`

3. Install deps in your app:

```bash
npm i @jtwebb/auth kysely pg @simplewebauthn/browser redis
```

4. Configure env:

- **`DATABASE_URL`**: Postgres URL
- **`SESSION_TOKEN_HMAC_SECRET`**: random secret
- **`BACKUP_CODE_HMAC_SECRET`**: random secret
- **`PASSWORD_PEPPER`**: random secret
- **`TOTP_ENCRYPTION_KEY`**: required to enable TOTP enrollment/verification
- **`APP_ORIGIN`**: e.g. `http://localhost:5173` (used for CSRF Origin checks + passkey origins)
- **`RP_ID`**: e.g. `localhost` (passkey relying party id)
- **`REDIS_URL`** (optional): if set, the example will use Redis for adapter rate limiting (shared across instances)

5. Apply auth DB migrations (Kysely migration functions shipped by this package):

- See `app/scripts/migrate-auth.ts`

## Notes

- **CSRF**: this example uses the library’s Origin checks (`assertSameOrigin`). Your forms/fetchers must be same-origin.
- **Kysely adapter**: uses `returning(...)` for consume-once operations (Postgres works well).
- **Redis rate limiting**: see `app/redis-rate-limiter.server.ts` and the `rateLimit.limiter` wiring in `app/auth.server.ts`.
