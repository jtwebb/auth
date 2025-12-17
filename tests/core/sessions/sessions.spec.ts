import { describe, expect, it } from 'vitest';
import { createAuthCore } from '../../../src/core/create-auth-core.js';
import type { AuthStorage, SessionRecord } from '../../../src/core/storage/auth-storage.js';

function makeMemoryStorage() {
  const sessions = new Map<string, SessionRecord>();

  const storage: AuthStorage = {
    users: { getUserIdByIdentifier: async () => null, createUser: async () => 'u1' as any },
    passwordCredentials: { getForUser: async () => null, upsertForUser: async () => undefined },
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
        sessions.set(s.tokenHash as any, s);
      },
      getSessionByTokenHash: async h => sessions.get(h as any) ?? null,
      touchSession: async (h, lastSeenAt) => {
        const s = sessions.get(h as any);
        if (s && !s.revokedAt) s.lastSeenAt = lastSeenAt;
      },
      revokeSession: async (h, revokedAt) => {
        const s = sessions.get(h as any);
        if (s) s.revokedAt = revokedAt;
      },
      revokeAllUserSessions: async (userId, revokedAt) => {
        for (const s of sessions.values()) {
          if (s.userId === userId) s.revokedAt = revokedAt;
        }
      },
      rotateSession: async (oldHash, newSession, revokedAt) => {
        const old = sessions.get(oldHash as any);
        if (old) old.revokedAt = revokedAt;
        sessions.set(newSession.tokenHash as any, newSession);
      }
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

  return { storage, sessions };
}

describe('core/sessions', () => {
  it('validates an existing session and touches lastSeenAt', async () => {
    const mem = makeMemoryStorage();
    const now = new Date('2025-01-01T00:00:00.000Z');
    const core = createAuthCore({
      storage: mem.storage,
      clock: { now: () => now },
      randomBytes: n => new Uint8Array(n).fill(9)
    });

    const created = core.createSessionToken();
    const tokenHash = core.hashSessionToken(created.sessionToken);
    await mem.storage.sessions.createSession({
      tokenHash,
      userId: 'u1' as any,
      createdAt: now,
      lastSeenAt: now,
      expiresAt: new Date(now.getTime() + 1000 * 60 * 60)
    });

    const later = new Date(now.getTime() + 1000 * 60);
    const res = await createAuthCore({
      storage: mem.storage,
      clock: { now: () => later }
    }).validateSession({
      sessionToken: created.sessionToken
    });
    expect(res.ok).toBe(true);
    if (res.ok) expect(res.userId).toBe('u1');
    expect(mem.sessions.get(tokenHash as any)?.lastSeenAt?.getTime()).toBe(later.getTime());
  });

  it('rotates session when rotateEveryMs has elapsed', async () => {
    const mem = makeMemoryStorage();
    const t0 = new Date('2025-01-01T00:00:00.000Z');
    let tick = 0;
    const core = createAuthCore({
      storage: mem.storage,
      clock: { now: () => new Date(t0.getTime() + tick) },
      randomBytes: n => new Uint8Array(n).fill(++tick),
      policy: { session: { rotateEveryMs: 1, absoluteTtlMs: 1000 * 60 * 60 } } as any
    });

    const initial = core.createSessionToken();
    const initialHash = core.hashSessionToken(initial.sessionToken);
    await mem.storage.sessions.createSession({
      tokenHash: initialHash,
      userId: 'u1' as any,
      createdAt: t0,
      lastSeenAt: t0,
      expiresAt: new Date(t0.getTime() + 1000 * 60 * 60)
    });

    // Advance beyond rotateEveryMs
    tick = 10;
    const res = await core.validateSession({ sessionToken: initial.sessionToken });
    expect(res.ok).toBe(true);
    if (res.ok) {
      expect(res.rotatedSession).toBeTruthy();
      expect(res.rotatedSession?.sessionToken).not.toBe(initial.sessionToken);
      expect(mem.sessions.get(initialHash as any)?.revokedAt).toBeTruthy();
    }
  });

  it('revokes a session token', async () => {
    const mem = makeMemoryStorage();
    const now = new Date();
    const core = createAuthCore({
      storage: mem.storage,
      clock: { now: () => now },
      randomBytes: n => new Uint8Array(n).fill(1)
    });
    const tok = core.createSessionToken();
    const h = core.hashSessionToken(tok.sessionToken);
    await mem.storage.sessions.createSession({
      tokenHash: h,
      userId: 'u1' as any,
      createdAt: now,
      lastSeenAt: now,
      expiresAt: new Date(now.getTime() + 1000 * 60 * 60)
    });

    await core.revokeSession({ sessionToken: tok.sessionToken });
    const res = await core.validateSession({ sessionToken: tok.sessionToken });
    expect(res).toMatchObject({ ok: false, reason: 'revoked' });
  });
});
