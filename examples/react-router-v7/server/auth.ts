import { createAuthCore } from '../../../src/core/create-auth-core.js';
import { createReactRouterAuthAdapter } from '../../../src/adapters/react-router/react-router-adapter.js';
import type { AuthStorage } from '../../../src/core/storage/auth-storage.js';

// In a real app, implement this against your DB.
const storage = {} as AuthStorage;

export const core = createAuthCore({
  storage,
  policy: {
    passkey: {
      rpId: 'example.com',
      rpName: 'Example',
      origins: ['https://example.com'],
      userVerification: 'preferred'
    }
  } as any,
  sessionTokenHashSecret: process.env.SESSION_TOKEN_HMAC_SECRET ?? 'dev-session-secret',
  backupCodeHashSecret: process.env.BACKUP_CODE_HMAC_SECRET ?? 'dev-backup-secret',
  passwordPepper: process.env.PASSWORD_PEPPER ?? 'dev-password-pepper'
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
