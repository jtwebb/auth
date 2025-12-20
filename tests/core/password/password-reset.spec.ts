import { describe, expect, it } from 'vitest';
import { createAuthCore } from '../../../src/core/create-auth-core.js';
import type {
  AuthStorage,
  PasswordCredentialRecord,
  SessionRecord
} from '../../../src/core/storage/auth-storage.js';
import type {
  PasswordResetTokenHash,
  SessionTokenHash,
  UserId
} from '../../../src/core/auth-types.js';

function makeMemoryStorage() {
  const usersByIdentifier = new Map<string, string>();
  const passwordByUserId = new Map<string, PasswordCredentialRecord>();
  const sessionsByHash = new Map<string, SessionRecord>();
  const resetTokens = new Map<
    string,
    { userId: string; createdAt: Date; expiresAt: Date; consumedAt: Date | null }
  >();

  const storage: AuthStorage = {
    users: {
      getUserIdByIdentifier: async identifier => (usersByIdentifier.get(identifier) as any) ?? null,
      createUser: async identifier => {
        const id = `u_${usersByIdentifier.size + 1}`;
        usersByIdentifier.set(identifier, id);
        return id as any;
      }
    },
    passwordCredentials: {
      getForUser: async userId => passwordByUserId.get(userId as any) ?? null,
      upsertForUser: async record => {
        passwordByUserId.set(record.userId as any, record);
      }
    },
    passwordResetTokens: {
      createToken: async record => {
        resetTokens.set(record.tokenHash as any, {
          userId: record.userId as any,
          createdAt: record.createdAt,
          expiresAt: record.expiresAt,
          consumedAt: null
        });
      },
      consumeToken: async (tokenHash: PasswordResetTokenHash, consumedAt: Date) => {
        const r = resetTokens.get(tokenHash as any);
        if (!r) return null;
        if (r.consumedAt) return null;
        if (r.expiresAt.getTime() <= consumedAt.getTime()) return null;
        r.consumedAt = consumedAt;
        return { userId: r.userId as any };
      }
    },
    challenges: { createChallenge: async () => undefined, consumeChallenge: async () => null },
    totp: {
      getEnabled: async () => null,
      getPending: async () => null,
      setPending: async () => undefined,
      enableFromPending: async () => undefined,
      disable: async () => undefined,
      updateLastUsedAt: async () => undefined
    },
    sessions: {
      createSession: async s => {
        sessionsByHash.set(s.tokenHash as any, s);
      },
      getSessionByTokenHash: async h => sessionsByHash.get(h as any) ?? null,
      touchSession: async () => undefined,
      revokeSession: async (h, revokedAt) => {
        const s = sessionsByHash.get(h as any);
        if (s) s.revokedAt = revokedAt;
      },
      revokeAllUserSessions: async (userId, revokedAt) => {
        for (const s of sessionsByHash.values()) {
          if (s.userId === userId) s.revokedAt = revokedAt;
        }
      },
      rotateSession: async () => undefined
    },
    webauthn: {
      listCredentialsForUser: async () => [],
      getCredentialById: async () => null,
      createCredential: async () => undefined,
      updateCredentialCounter: async () => undefined
    },
    backupCodes: {
      replaceCodes: async () => undefined,
      consumeCode: async () => false,
      countRemaining: async () => 0
    }
  };

  return { storage, usersByIdentifier, passwordByUserId, sessionsByHash, resetTokens };
}

describe('core/password reset', () => {
  it('creates a single-use reset token and updates password + revokes sessions on use', async () => {
    const mem = makeMemoryStorage();
    const base = new Date('2025-01-01T00:00:00.000Z');
    let tick = 0;
    const core = createAuthCore({
      storage: mem.storage,
      clock: { now: () => new Date(base.getTime() + tick) },
      randomBytes: n => new Uint8Array(n).fill(7),
      passwordResetTokenHashSecret: 'reset-secret'
    });

    const reg = await core.registerPassword({
      identifier: 'a@example.com',
      password: 'long-enough-password'
    });

    // Create another session to prove revokeAllUserSessions happens
    const tok2 = core.createSessionToken();
    await mem.storage.sessions.createSession({
      tokenHash: core.hashSessionToken(tok2.sessionToken) as unknown as SessionTokenHash,
      userId: reg.userId as unknown as UserId,
      createdAt: new Date(base.getTime() + tick),
      expiresAt: new Date(base.getTime() + tick + 1000 * 60 * 60)
    });

    const { token } = await core.createPasswordResetToken({ userId: reg.userId });
    tick += 1000;

    const sessionsBeforeReset = [...mem.sessionsByHash.values()];
    const out = await core.resetPasswordWithToken({ token, newPassword: 'even-longer-password' });
    expect(out.ok).toBe(true);
    expect(out.userId).toBe(reg.userId);

    // Token is single-use
    await expect(
      core.resetPasswordWithToken({ token, newPassword: 'another-password' })
    ).rejects.toMatchObject({ code: 'password_reset_invalid' });

    // Old password should no longer work
    await expect(
      core.loginPassword({ identifier: 'a@example.com', password: 'long-enough-password' })
    ).rejects.toMatchObject({ code: 'password_invalid' });

    // New password works
    await core.loginPassword({ identifier: 'a@example.com', password: 'even-longer-password' });

    // Sessions that existed before reset are revoked
    expect(sessionsBeforeReset.every(s => s.revokedAt)).toBe(true);
  });

  it('rejects expired reset tokens', async () => {
    const mem = makeMemoryStorage();
    const base = new Date('2025-01-01T00:00:00.000Z');
    let tick = 0;
    const core = createAuthCore({
      storage: mem.storage,
      clock: { now: () => new Date(base.getTime() + tick) },
      randomBytes: n => new Uint8Array(n).fill(7),
      policy: { passwordReset: { tokenTtlMs: 60_000 } } as any
    });

    const reg = await core.registerPassword({
      identifier: 'a@example.com',
      password: 'long-enough-password'
    });
    const { token } = await core.createPasswordResetToken({ userId: reg.userId });

    tick += 61_000; // expire
    await expect(
      core.resetPasswordWithToken({ token, newPassword: 'even-longer-password' })
    ).rejects.toMatchObject({
      code: 'password_reset_invalid'
    });
  });
});
