import { createAuthCore } from '@jtwebb/auth/core';
import { createReactRouterAuthAdapter } from '@jtwebb/auth/react-router';
import { createPgAuthStorage } from '@jtwebb/auth/pg';
import { Pool } from 'pg';

/**
 * This example uses the `pg` adapter because it's the simplest + most explicit.
 *
 * 1) Apply migrations:
 *    - `psql "$DATABASE_URL" -f node_modules/@jtwebb/auth/dist/adapters/pg/migrations/001_init.sql`
 * 2) Configure `DATABASE_URL`.
 */
const pool = new Pool({
  connectionString:
    process.env.DATABASE_URL ?? 'postgres://postgres:postgres@localhost:5432/postgres'
});

export const storage = createPgAuthStorage({
  pool
  // Optional: set schema/prefix/table overrides here.
  // schema: 'public',
  // tablePrefix: 'app_',
  // tables: { users: 'auth_users' },
});

export const core = createAuthCore({
  storage,
  policy: {
    passkey: {
      // For real apps: set these to your real domain + HTTPS origins.
      rpId: 'localhost',
      rpName: 'React Router v7 example',
      origins: ['http://localhost:5173'],
      userVerification: 'preferred'
    }
  },
  sessionTokenHashSecret: process.env.SESSION_TOKEN_HMAC_SECRET ?? 'dev-session-secret',
  backupCodeHashSecret: process.env.BACKUP_CODE_HMAC_SECRET ?? 'dev-backup-secret',
  passwordPepper: process.env.PASSWORD_PEPPER ?? 'dev-password-pepper'
  // Optional: enable TOTP features by providing an encryption key:
  // totpEncryptionKey: process.env.TOTP_ENCRYPTION_KEY!,
});

export const auth = createReactRouterAuthAdapter({
  core,
  sessionCookie: {
    name: 'sid',
    path: '/',
    httpOnly: true,
    secure: true,
    sameSite: 'lax'
  }
});
