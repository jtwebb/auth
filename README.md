# `@jtwebb/auth`

Secure, framework-agnostic authentication building blocks for Node 20+:

- **Core**: password + passkeys (WebAuthn) + **TOTP 2FA** + backup codes + DB-backed sessions (opaque token, hashed in DB)
- **Adapters**: React Router v7 first (`Request`/`Response` based)
- **React helpers**: passkey flows, hooks, and minimal UI components

## Install

```bash
npm i @jtwebb/auth
```

## Package entrypoints

- `@jtwebb/auth/core`
- `@jtwebb/auth/react-router`
- `@jtwebb/auth/react`
- `@jtwebb/auth/pg`
- `@jtwebb/auth/kysely`

## Core usage (server)

### 1) Implement `AuthStorage`

Core is DB-agnostic. You implement `AuthStorage` against your DB. The key security properties:

- **Sessions**: store only `tokenHash` server-side (never plaintext session tokens)
- **Passwords**: store only Argon2id PHC hashes (never plaintext)
- **Passkeys**: store credential `id` (base64url), `publicKey`, and `counter`
- **Challenges + backup codes**: consume exactly once (atomic)

#### Optional: database adapters

If you don't want to hand-roll `AuthStorage`, there are optional adapters:

- `@jtwebb/auth/pg`
- `@jtwebb/auth/kysely`

See `docs/database-adapters.md`.

#### Sample Postgres `AuthStorage` (schema + implementation sketch)

Below is a minimal Postgres schema and a `pg`-style implementation sketch. It’s intentionally small, but shows the **security-critical patterns**:

- **Atomic single-use**: challenges and backup codes are consumed with a single SQL statement (`DELETE … RETURNING` / `UPDATE … WHERE … RETURNING`)
- **Session rotation**: insert new session + revoke old session **in a transaction**
- **No plaintext secrets**: store only password hashes, session token hashes, backup-code hashes, and **encrypted** TOTP secrets

##### 1) Schema (SQL)

```sql
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE auth_users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  identifier text NOT NULL UNIQUE,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE auth_password_credentials (
  user_id uuid PRIMARY KEY REFERENCES auth_users(id) ON DELETE CASCADE,
  password_hash text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz
);

CREATE TABLE auth_webauthn_credentials (
  id text PRIMARY KEY, -- credential ID (base64url)
  user_id uuid NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
  credential_id text NOT NULL UNIQUE,
  public_key bytea NOT NULL,
  counter integer NOT NULL,
  transports text[] NULL,
  credential_device_type text NULL,
  credential_backed_up boolean NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz
);

CREATE TABLE auth_challenges (
  id text PRIMARY KEY,
  type text NOT NULL, -- passkey_register | passkey_login | totp_pending
  user_id uuid NULL REFERENCES auth_users(id) ON DELETE CASCADE,
  challenge text NOT NULL,
  expires_at timestamptz NOT NULL
);
CREATE INDEX auth_challenges_expires_at_idx ON auth_challenges(expires_at);

CREATE TABLE auth_sessions (
  token_hash text PRIMARY KEY, -- hex SHA-256 or HMAC-SHA256
  user_id uuid NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL,
  last_seen_at timestamptz NULL,
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz NULL,
  rotated_from_hash text NULL
);
CREATE INDEX auth_sessions_user_id_idx ON auth_sessions(user_id);
CREATE INDEX auth_sessions_expires_at_idx ON auth_sessions(expires_at);

CREATE TABLE auth_backup_codes (
  user_id uuid NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
  code_hash text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  consumed_at timestamptz NULL,
  PRIMARY KEY (user_id, code_hash)
);
CREATE INDEX auth_backup_codes_user_id_consumed_idx ON auth_backup_codes(user_id, consumed_at);

CREATE TABLE auth_totp (
  user_id uuid PRIMARY KEY REFERENCES auth_users(id) ON DELETE CASCADE,
  encrypted_secret text NOT NULL,
  enabled_at timestamptz NULL,
  pending_created_at timestamptz NULL,
  last_used_at timestamptz NULL
);
```

##### 2) Implementation sketch (TypeScript)

```ts
import type { Pool, PoolClient } from 'pg';
import type {
  AuthStorage,
  ChallengeId,
  PasswordCredentialRecord,
  SessionRecord,
  SessionTokenHash,
  StoredChallenge,
  UserId,
  WebAuthnCredentialId,
  WebAuthnCredentialRecord
} from '@jtwebb/auth/core';
import type { AuthenticatorTransportFuture, CredentialDeviceType } from '@simplewebauthn/server';

function toDate(v: Date | string | number): Date {
  return v instanceof Date ? v : new Date(v);
}

function toOptionalDate(v: Date | string | number | null | undefined): Date | undefined {
  if (v == null) return undefined;
  return toDate(v);
}

// Core uses "branded" string types (UserId, ChallengeId, SessionTokenHash, ...)
// so apps typically centralize the casts in tiny helpers like these.
function asUserId(v: string): UserId {
  return v as UserId;
}
function asChallengeId(v: string): ChallengeId {
  return v as ChallengeId;
}
function asSessionTokenHash(v: string): SessionTokenHash {
  return v as SessionTokenHash;
}
function asWebAuthnCredentialId(v: string): WebAuthnCredentialId {
  return v as WebAuthnCredentialId;
}

export function createPostgresAuthStorage(pool: Pool): AuthStorage {
  return {
    users: {
      async getUserIdByIdentifier(identifier) {
        const res = await pool.query<{ id: string }>(
          `SELECT id FROM auth_users WHERE identifier = $1`,
          [identifier]
        );
        const id = res.rows[0]?.id;
        return id ? asUserId(id) : null;
      },
      async createUser(identifier) {
        const res = await pool.query<{ id: string }>(
          `INSERT INTO auth_users (identifier) VALUES ($1) RETURNING id`,
          [identifier]
        );
        return asUserId(res.rows[0].id);
      }
    },

    passwordCredentials: {
      async getForUser(userId) {
        const res = await pool.query<{
          user_id: string;
          password_hash: string;
          created_at: Date | string;
          updated_at: Date | string | null;
        }>(
          `SELECT user_id, password_hash, created_at, updated_at
           FROM auth_password_credentials
           WHERE user_id = $1`,
          [userId]
        );
        const r = res.rows[0];
        if (!r) return null;
        const out: PasswordCredentialRecord = {
          userId: asUserId(r.user_id),
          passwordHash: r.password_hash,
          createdAt: toDate(r.created_at),
          updatedAt: toOptionalDate(r.updated_at)
        };
        return out;
      },
      async upsertForUser(record) {
        await pool.query(
          `INSERT INTO auth_password_credentials (user_id, password_hash, created_at, updated_at)
           VALUES ($1, $2, $3, $4)
           ON CONFLICT (user_id)
           DO UPDATE SET password_hash = EXCLUDED.password_hash, updated_at = EXCLUDED.updated_at`,
          [record.userId, record.passwordHash, record.createdAt, record.updatedAt ?? null]
        );
      }
    },

    challenges: {
      async createChallenge(ch) {
        await pool.query(
          `INSERT INTO auth_challenges (id, type, user_id, challenge, expires_at)
           VALUES ($1, $2, $3, $4, $5)`,
          [ch.id, ch.type, ch.userId ?? null, ch.challenge, ch.expiresAt]
        );
      },
      async consumeChallenge(id) {
        const res = await pool.query<{
          id: string;
          type: StoredChallenge['type'];
          user_id: string | null;
          challenge: string;
          expires_at: Date | string;
        }>(
          `DELETE FROM auth_challenges
           WHERE id = $1
           RETURNING id, type, user_id, challenge, expires_at`,
          [id]
        );
        const r = res.rows[0];
        if (!r) return null;
        const out: StoredChallenge = {
          id: asChallengeId(r.id),
          type: r.type,
          userId: r.user_id ? asUserId(r.user_id) : undefined,
          challenge: r.challenge,
          expiresAt: toDate(r.expires_at)
        };
        return out;
      }
    },

    totp: {
      async getEnabled(userId) {
        const res = await pool.query<{
          encrypted_secret: string;
          enabled_at: Date | string;
          last_used_at: Date | string | null;
        }>(
          `SELECT encrypted_secret, enabled_at, last_used_at
           FROM auth_totp
           WHERE user_id = $1 AND enabled_at IS NOT NULL`,
          [userId]
        );
        const r = res.rows[0];
        if (!r) return null;
        return {
          encryptedSecret: r.encrypted_secret,
          enabledAt: toDate(r.enabled_at),
          lastUsedAt: toOptionalDate(r.last_used_at)
        };
      },
      async getPending(userId) {
        const res = await pool.query<{
          encrypted_secret: string;
          pending_created_at: Date | string;
        }>(
          `SELECT encrypted_secret, pending_created_at
           FROM auth_totp
           WHERE user_id = $1 AND enabled_at IS NULL AND pending_created_at IS NOT NULL`,
          [userId]
        );
        const r = res.rows[0];
        if (!r) return null;
        return { encryptedSecret: r.encrypted_secret, createdAt: toDate(r.pending_created_at) };
      },
      async setPending(userId, encryptedSecret, createdAt) {
        await pool.query(
          `INSERT INTO auth_totp (user_id, encrypted_secret, enabled_at, pending_created_at, last_used_at)
           VALUES ($1, $2, NULL, $3, NULL)
           ON CONFLICT (user_id)
           DO UPDATE SET encrypted_secret = EXCLUDED.encrypted_secret, enabled_at = NULL, pending_created_at = EXCLUDED.pending_created_at`,
          [userId, encryptedSecret, createdAt]
        );
      },
      async enableFromPending(userId, enabledAt) {
        await pool.query(
          `UPDATE auth_totp
           SET enabled_at = $2, pending_created_at = NULL
           WHERE user_id = $1 AND enabled_at IS NULL AND pending_created_at IS NOT NULL`,
          [userId, enabledAt]
        );
      },
      async disable(userId, _disabledAt) {
        await pool.query(`DELETE FROM auth_totp WHERE user_id = $1`, [userId]);
      },
      async updateLastUsedAt(userId, lastUsedAt) {
        await pool.query(`UPDATE auth_totp SET last_used_at = $2 WHERE user_id = $1`, [
          userId,
          lastUsedAt
        ]);
      }
    },

    sessions: {
      async createSession(s) {
        await pool.query(
          `INSERT INTO auth_sessions (token_hash, user_id, created_at, last_seen_at, expires_at, revoked_at, rotated_from_hash)
           VALUES ($1, $2, $3, $4, $5, $6, $7)`,
          [
            s.tokenHash,
            s.userId,
            s.createdAt,
            s.lastSeenAt ?? null,
            s.expiresAt,
            s.revokedAt ?? null,
            s.rotatedFromHash ?? null
          ]
        );
      },
      async getSessionByTokenHash(tokenHash) {
        const res = await pool.query<{
          token_hash: string;
          user_id: string;
          created_at: Date | string;
          last_seen_at: Date | string | null;
          expires_at: Date | string;
          revoked_at: Date | string | null;
          rotated_from_hash: string | null;
        }>(
          `SELECT token_hash, user_id, created_at, last_seen_at, expires_at, revoked_at, rotated_from_hash
           FROM auth_sessions
           WHERE token_hash = $1`,
          [tokenHash]
        );
        const r = res.rows[0];
        if (!r) return null;
        const out: SessionRecord = {
          tokenHash: asSessionTokenHash(r.token_hash),
          userId: asUserId(r.user_id),
          createdAt: toDate(r.created_at),
          lastSeenAt: toOptionalDate(r.last_seen_at),
          expiresAt: toDate(r.expires_at),
          revokedAt: toOptionalDate(r.revoked_at),
          rotatedFromHash: r.rotated_from_hash ? asSessionTokenHash(r.rotated_from_hash) : undefined
        };
        return out;
      },
      async touchSession(tokenHash, lastSeenAt) {
        await pool.query(
          `UPDATE auth_sessions SET last_seen_at = $2 WHERE token_hash = $1 AND revoked_at IS NULL`,
          [tokenHash, lastSeenAt]
        );
      },
      async revokeSession(tokenHash, revokedAt) {
        await pool.query(`UPDATE auth_sessions SET revoked_at = $2 WHERE token_hash = $1`, [
          tokenHash,
          revokedAt
        ]);
      },
      async revokeAllUserSessions(userId, revokedAt) {
        await pool.query(`UPDATE auth_sessions SET revoked_at = $2 WHERE user_id = $1`, [
          userId,
          revokedAt
        ]);
      },
      async rotateSession(oldTokenHash, newSession, revokedAt) {
        await withTx(pool, async tx => {
          await tx.query(
            `INSERT INTO auth_sessions (token_hash, user_id, created_at, last_seen_at, expires_at, revoked_at, rotated_from_hash)
             VALUES ($1, $2, $3, $4, $5, NULL, $6)`,
            [
              newSession.tokenHash,
              newSession.userId,
              newSession.createdAt,
              newSession.lastSeenAt ?? null,
              newSession.expiresAt,
              newSession.rotatedFromHash ?? null
            ]
          );
          await tx.query(`UPDATE auth_sessions SET revoked_at = $2 WHERE token_hash = $1`, [
            oldTokenHash,
            revokedAt
          ]);
        });
      }
    },

    backupCodes: {
      async replaceCodes(userId, codes, _rotatedAt) {
        await withTx(pool, async tx => {
          await tx.query(`DELETE FROM auth_backup_codes WHERE user_id = $1`, [userId]);
          for (const c of codes) {
            await tx.query(
              `INSERT INTO auth_backup_codes (user_id, code_hash, created_at, consumed_at)
               VALUES ($1, $2, $3, NULL)`,
              [userId, c.codeHash, c.createdAt]
            );
          }
        });
      },
      async consumeCode(userId, codeHash, consumedAt) {
        const res = await pool.query(
          `UPDATE auth_backup_codes
           SET consumed_at = $3
           WHERE user_id = $1 AND code_hash = $2 AND consumed_at IS NULL
           RETURNING 1`,
          [userId, codeHash, consumedAt]
        );
        return res.rowCount === 1;
      },
      async countRemaining(userId) {
        const res = await pool.query<{ n: string | number }>(
          `SELECT COUNT(*)::int AS n
           FROM auth_backup_codes
           WHERE user_id = $1 AND consumed_at IS NULL`,
          [userId]
        );
        const n = res.rows[0]?.n ?? 0;
        return typeof n === 'number' ? n : Number.parseInt(n, 10);
      }
    },

    webauthn: {
      async listCredentialsForUser(userId) {
        const res = await pool.query<{
          id: string;
          user_id: string;
          credential_id: string;
          public_key: Buffer;
          counter: number;
          transports: string[] | null;
          credential_device_type: string | null;
          credential_backed_up: boolean | null;
          created_at: Date | string;
          updated_at: Date | string | null;
        }>(
          `SELECT id, user_id, credential_id, public_key, counter, transports, credential_device_type, credential_backed_up, created_at, updated_at
           FROM auth_webauthn_credentials
           WHERE user_id = $1`,
          [userId]
        );
        return res.rows.map(
          (r): WebAuthnCredentialRecord => ({
            id: asWebAuthnCredentialId(r.id),
            userId: asUserId(r.user_id),
            credentialId: r.credential_id,
            publicKey: new Uint8Array(r.public_key),
            counter: r.counter,
            transports: (r.transports ?? undefined) as AuthenticatorTransportFuture[] | undefined,
            credentialDeviceType: (r.credential_device_type ?? undefined) as
              | CredentialDeviceType
              | undefined,
            credentialBackedUp: r.credential_backed_up ?? undefined,
            createdAt: toDate(r.created_at),
            updatedAt: toOptionalDate(r.updated_at)
          })
        );
      },
      async getCredentialById(id) {
        const res = await pool.query<{
          id: string;
          user_id: string;
          credential_id: string;
          public_key: Buffer;
          counter: number;
          transports: string[] | null;
          credential_device_type: string | null;
          credential_backed_up: boolean | null;
          created_at: Date | string;
          updated_at: Date | string | null;
        }>(
          `SELECT id, user_id, credential_id, public_key, counter, transports, credential_device_type, credential_backed_up, created_at, updated_at
           FROM auth_webauthn_credentials
           WHERE id = $1`,
          [id]
        );
        const r = res.rows[0];
        if (!r) return null;
        const out: WebAuthnCredentialRecord = {
          id: asWebAuthnCredentialId(r.id),
          userId: asUserId(r.user_id),
          credentialId: r.credential_id,
          publicKey: new Uint8Array(r.public_key),
          counter: r.counter,
          transports: (r.transports ?? undefined) as AuthenticatorTransportFuture[] | undefined,
          credentialDeviceType: (r.credential_device_type ?? undefined) as
            | CredentialDeviceType
            | undefined,
          credentialBackedUp: r.credential_backed_up ?? undefined,
          createdAt: toDate(r.created_at),
          updatedAt: toOptionalDate(r.updated_at)
        };
        return out;
      },
      async createCredential(record) {
        await pool.query(
          `INSERT INTO auth_webauthn_credentials
           (id, user_id, credential_id, public_key, counter, transports, credential_device_type, credential_backed_up, created_at, updated_at)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
          [
            record.id,
            record.userId,
            record.credentialId,
            Buffer.from(record.publicKey),
            record.counter,
            record.transports ?? null,
            record.credentialDeviceType ?? null,
            record.credentialBackedUp ?? null,
            record.createdAt,
            record.updatedAt ?? null
          ]
        );
      },
      async updateCredentialCounter(id, counter, updatedAt) {
        await pool.query(
          `UPDATE auth_webauthn_credentials SET counter = $2, updated_at = $3 WHERE id = $1`,
          [id, counter, updatedAt]
        );
      }
    }
  };
}

async function withTx<T>(pool: Pool, fn: (tx: PoolClient) => Promise<T>): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const out = await fn(client);
    await client.query('COMMIT');
    return out;
  } catch (e) {
    await client.query('ROLLBACK');
    throw e;
  } finally {
    client.release();
  }
}
```

### 2) Create `AuthCore`

```ts
import { createAuthCore } from '@jtwebb/auth/core';

const core = createAuthCore({
  storage,
  // Optional: use opinionated presets ("strict" | "balanced" | "legacy")
  // securityProfile: 'strict',
  policy: {
    passkey: {
      rpId: 'example.com',
      rpName: 'Example',
      origins: ['https://example.com'],
      userVerification: 'preferred'
    },
    totp: {
      issuer: 'Example',
      digits: 6,
      periodSeconds: 30,
      allowedSkewSteps: 1
    }
  },
  // Recommended: secrets for hashing tokens/codes
  sessionTokenHashSecret: process.env.SESSION_TOKEN_HMAC_SECRET!,
  backupCodeHashSecret: process.env.BACKUP_CODE_HMAC_SECRET!,
  passwordPepper: process.env.PASSWORD_PEPPER!,
  // Required for TOTP (2FA): encrypt TOTP secrets at rest
  totpEncryptionKey: process.env.TOTP_ENCRYPTION_KEY!
});
```

### TOTP encryption key rotation (recommended)

`totpEncryptionKey` supports two modes:

- **Legacy (single key)**: pass a string/bytes. Existing ciphertexts are stored in a v1 format (no key id).
- **Key ring (rotatable)**: pass `{ primaryKeyId, keys }`. New ciphertexts are stored in a v2 format
  with an embedded key id, and decryption can use **multiple keys** (to support rotation).

Example key ring:

```ts
const core = createAuthCore({
  storage,
  totpEncryptionKey: {
    // New enrollments will encrypt using this key id (v2.<kid>...)
    primaryKeyId: 'k2',
    // Keep old keys for decryption of existing secrets during rotation
    keys: {
      k1: process.env.TOTP_ENCRYPTION_KEY_OLD!,
      k2: process.env.TOTP_ENCRYPTION_KEY_CURRENT!
    }
  }
});
```

Rotation procedure:

- **Deploy** with `{ primaryKeyId: "new", keys: { old, new } }`
- After all old secrets have been naturally re-enrolled/rotated (or you migrate them), **remove** the old key

## React Router v7 adapter usage

This adapter intentionally **does not import react-router packages**. It operates on standard `Request`/`Response`
objects used by React Router actions/loaders.

```ts
import { createReactRouterAuthAdapter } from '@jtwebb/auth/react-router';

export const auth = createReactRouterAuthAdapter({
  core,
  // Optional: adapter defaults preset ("strict" | "balanced" | "legacy")
  // securityProfile: 'strict',
  sessionCookie: {
    name: 'sid',
    path: '/',
    httpOnly: true,
    secure: true,
    sameSite: 'lax'
  },
  // Used during 2FA step-up (httpOnly cookie holding the pending token)
  totpPendingCookie: {
    name: 'totp',
    path: '/',
    httpOnly: true,
    secure: true,
    sameSite: 'lax',
    maxAgeSeconds: 60 * 5
  },
  twoFactorRedirectTo: '/two-factor'
});
```

### Guard a loader

```ts
export async function loader({ request }: { request: Request }) {
  const { userId, headers } = await auth.requireUser(request, { redirectTo: '/login' });
  return new Response(JSON.stringify({ userId }), { headers });
}
```

### Actions

- Password login: `auth.actions.passwordLogin(request, { redirectTo: "/" })`
- Password register: `auth.actions.passwordRegister(request, { redirectTo: "/" })`
- Passkey login: `auth.actions.passkeyLoginStart(request)` then `auth.actions.passkeyLoginFinish(request, { redirectTo: "/" })`
- Logout: `auth.logout(request, { redirectTo: "/login" })`
- TOTP enrollment: `auth.actions.totpEnrollmentStart(request)` then `auth.actions.totpEnrollmentFinish(request)`
- TOTP verification (step-up): `auth.actions.totpVerify(request, { redirectTo: "/" })`

### CSRF protection (double-submit token, enabled by default)

The React Router adapter enforces CSRF protection on state-changing actions by default:

- **Origin/Referer** must match your allowed origins
- **Double-submit token**: a non-HttpOnly `csrf` cookie must match a submitted token
  - form posts: include a `csrfToken` field
  - fetch/XHR: include an `x-csrf-token` header

Mint a CSRF token cookie in a loader and embed it in your form:

```ts
export async function loader({ request }: { request: Request }) {
  const { token, headers } = auth.csrf.getToken(request);
  return new Response(JSON.stringify({ csrfToken: token }), { headers });
}

export async function action({ request }: { request: Request }) {
  return await auth.actions.passwordLogin(request, { redirectTo: '/' });
}
```

Then include it in your POST:

- HTML form: add `<input type="hidden" name="csrfToken" value="...">`
- fetch: set header `x-csrf-token: <token>` (and ensure cookie is sent)

To disable (not recommended):

```ts
createReactRouterAuthAdapter({
  core,
  sessionCookie,
  csrf: { doubleSubmit: { enabled: false } } // keeps Origin/Referer checks only
  // or csrf: { enabled: false } to disable all CSRF checks
});
```

### 2FA (TOTP) flow (server)

- If TOTP is enabled for a user, **password/passkey login will redirect to** `twoFactorRedirectTo` and set an **httpOnly** `totp` cookie.
- Your `/two-factor` page should POST a form with `code` to the `totpVerify` action endpoint.

## React helpers usage (browser)

### Passkey flow (recommended)

```ts
import { createPasskeyFlows } from '@jtwebb/auth/react';

const passkeys = createPasskeyFlows({
  registrationStartUrl: '/api/passkeys/register/start',
  registrationFinishUrl: '/api/passkeys/register/finish',
  loginStartUrl: '/api/passkeys/login/start',
  loginFinishUrl: '/api/passkeys/login/finish'
});

await passkeys.login(); // passkey-first (discoverable)
```

### Components

- `LoginForm`
- `PasskeyLoginButton`
- `PasskeyRegistrationButton`
- `BackupCodesDisplay`
- `BackupCodeRedeemForm`
- `TotpSetup`
- `TotpVerifyForm`

## Security notes (must read)

See `SECURITY.md` and `docs/production-hardening.md`.

## Password reset / account recovery (server)

This library includes **primitives** for password reset tokens (it does not send email for you).

Security properties:

- Reset tokens are **random**, and only a **hash** is stored server-side (never plaintext).
- Tokens are **single-use** and **expire** (default 15 minutes).
- On successful reset, the library **revokes all user sessions by default**.

Typical flow:

1. User submits identifier (email/username). Your server calls:

```ts
const out = await core.startPasswordReset({ identifier });
// IMPORTANT: do not reveal out.created to the end user (avoid enumeration).
// If out.created === true, send the reset link containing out.token to the user via email/SMS.
```

2. User clicks reset link and submits a new password along with the token:

```ts
await core.resetPasswordWithToken({
  token,
  newPassword,
  revokeAllUserSessions: true // default
});
```

Hardening recommendations:

- Enable adapter **rate limiting + progressive lockouts** on password reset endpoints
- Store `passwordResetTokenHashSecret` in a secrets manager/KMS (recommended)
- Consider additional verification for high-risk accounts (step-up via passkey/TOTP)

## Rate limiting (recommended)

This library exposes an `onAuthAttempt` hook for **logging/auditing/rate-limit tracking**.

Important: `onAuthAttempt` is intentionally **non-blocking** (errors are swallowed), so to _enforce_
rate limits you should also do a pre-check in your adapter/route handler.

This repo includes a small in-memory helper (`InMemoryRateLimiter`) suitable for development and
single-instance deployments.

Example:

```ts
import { createAuthCore, InMemoryRateLimiter, createOnAuthAttemptRateLimiter } from '@jtwebb/auth';

const limiter = new InMemoryRateLimiter();
const rl = createOnAuthAttemptRateLimiter({
  limiter,
  // 10 failures per 15 minutes
  rule: { windowMs: 15 * 60_000, max: 10 },
  // Count failures per identifier (you can add per-IP keys in your adapter where you have request context).
  keys: e => (e.type === 'password_login' && !e.ok ? [`login:id:${e.identifier}`] : [])
});

const core = createAuthCore({
  storage,
  onAuthAttempt: rl.onAuthAttempt
});

// In your route handler/action (where you have request context), enforce BEFORE doing auth work:
rl.assertAllowed([`login:id:${identifier}`]);
```

### Progressive delays + temporary lockouts (enabled by default in the React Router adapter)

In addition to fixed-window rate limiting, the React Router adapter applies **progressive delays**
and **temporary lockouts** after repeated failures (and **resets on success**). This helps against
distributed attacks where simple per-IP limits may be bypassed.

- **What it affects (defaults)**: password login, TOTP verify, and passkey finish.
- **Response**: HTTP **429** with a `Retry-After` header when delayed/locked.

To configure (or disable) it:

```ts
import { createReactRouterAuthAdapter } from '@jtwebb/auth/react-router';

export const auth = createReactRouterAuthAdapter({
  core,
  sessionCookie: { name: 'sid', path: '/', httpOnly: true, secure: true, sameSite: 'lax' },
  rateLimit: {
    // disable entirely:
    // enabled: false,

    progressiveDelay: {
      // disable progressive delays but keep fixed-window rate limits:
      // enabled: false,

      // override defaults (example: password login per identifier)
      rules: {
        passwordLoginPerIdentifier: {
          failureWindowMs: 15 * 60_000,
          startAfterFailures: 3,
          baseDelayMs: 1_000,
          factor: 2,
          maxDelayMs: 60_000,
          lockoutAfterFailures: 10,
          lockoutMs: 15 * 60_000
        }
      }
    }
  }
});
```

Production guidance:

- Use a shared store (Redis) with atomic increments (multi-instance safe)
- Key on both **client id** (IP/device) and **account/identifier**
- Prefer counting **failures only**, and consider separate limits for:
  - password login
  - TOTP verify
  - passkey finish
