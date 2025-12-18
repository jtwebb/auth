import { createAuthCore } from '@jtwebb/auth/core';
import { createKyselyAuthStorage } from '@jtwebb/auth/kysely';
import { assertSameOrigin } from '@jtwebb/auth/react-router';
import { createReactRouterAuthAdapter } from '@jtwebb/auth/react-router';
import { db } from './db.server';

export const APP_ORIGIN = process.env.APP_ORIGIN ?? 'http://localhost:5173';
export const RP_ID = process.env.RP_ID ?? 'localhost';

export const storage = createKyselyAuthStorage({
  db
  // Optional: set schema/prefix/table overrides here.
  // tablePrefix: "app_",
});

export const core = createAuthCore({
  storage,
  policy: {
    passkey: {
      rpId: RP_ID,
      rpName: 'React Router v7 Framework + @jtwebb/auth (Kysely)',
      origins: [APP_ORIGIN],
      userVerification: 'preferred'
    }
  },
  sessionTokenHashSecret: process.env.SESSION_TOKEN_HMAC_SECRET ?? 'dev-session-secret',
  backupCodeHashSecret: process.env.BACKUP_CODE_HMAC_SECRET ?? 'dev-backup-secret',
  passwordPepper: process.env.PASSWORD_PEPPER ?? 'dev-password-pepper',
  ...(process.env.TOTP_ENCRYPTION_KEY ? { totpEncryptionKey: process.env.TOTP_ENCRYPTION_KEY } : {})
});

export const sessionCookie = {
  name: 'sid',
  path: '/',
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'lax' as const
};

export const totpPendingCookie = {
  name: 'totp',
  path: '/',
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'lax' as const,
  maxAgeSeconds: 60 * 5
};

export const allowedOrigins = [APP_ORIGIN] as const;

export function assertCsrf(request: Request) {
  // This library's CSRF strategy is same-origin enforcement via the Origin header.
  assertSameOrigin(request, allowedOrigins);
}

export const auth = createReactRouterAuthAdapter({
  core,
  sessionCookie,
  totpPendingCookie
  // Optional override:
  // csrf: { enabled: true, allowedOrigins }
});
