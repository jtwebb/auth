import { describe, expect, it } from 'vitest';
import { createAuthCore } from '../../../src/core/create-auth-core.js';
import type {
  AuthStorage,
  SessionRecord,
  StoredChallenge
} from '../../../src/core/storage/auth-storage.js';
import { createHmac } from 'node:crypto';

function makeMemoryStorage() {
  const pending = new Map<string, { encryptedSecret: string; createdAt: Date }>();
  const enabled = new Map<
    string,
    { encryptedSecret: string; enabledAt: Date; lastUsedAt?: Date; lastUsedStep?: number }
  >();
  const challenges = new Map<string, StoredChallenge>();
  const sessions = new Map<string, SessionRecord>();

  const storage: AuthStorage = {
    users: { getUserIdByIdentifier: async () => null, createUser: async () => 'u1' as any },
    passwordCredentials: { getForUser: async () => null, upsertForUser: async () => undefined },
    challenges: {
      createChallenge: async c => {
        challenges.set(c.id as any, c);
      },
      consumeChallenge: async id => {
        const c = challenges.get(id as any) ?? null;
        if (c) challenges.delete(id as any);
        return c;
      }
    },
    totp: {
      // Return a deliberately "stale" view of lastUsedStep to simulate concurrent requests
      // that both verify against the same prior state. The atomic method should catch replays.
      getEnabled: async userId => {
        const e = enabled.get(userId as any) ?? null;
        if (!e) return null;
        return { ...e, lastUsedAt: e.lastUsedAt, lastUsedStep: 0 };
      },
      getPending: async userId => pending.get(userId as any) ?? null,
      setPending: async (userId, encryptedSecret, createdAt) => {
        pending.set(userId as any, { encryptedSecret, createdAt });
      },
      enableFromPending: async (userId, enabledAt) => {
        const p = pending.get(userId as any);
        if (!p) throw new Error('no pending');
        pending.delete(userId as any);
        enabled.set(userId as any, { encryptedSecret: p.encryptedSecret, enabledAt });
      },
      disable: async userId => {
        pending.delete(userId as any);
        enabled.delete(userId as any);
      },
      updateLastUsedAt: async (userId, lastUsedAt) => {
        const e = enabled.get(userId as any);
        if (e) e.lastUsedAt = lastUsedAt;
      },
      updateLastUsedStepIfGreater: async ({ userId, step, usedAt }) => {
        const e = enabled.get(userId as any);
        if (!e) return false;
        const cur = e.lastUsedStep ?? 0;
        if (step <= cur) return false;
        e.lastUsedStep = step;
        e.lastUsedAt = usedAt;
        return true;
      }
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
      revokeSession: async () => undefined,
      revokeAllUserSessions: async () => undefined,
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

  return { storage, challenges, sessions, enabled };
}

describe('core/totp', () => {
  it('enrolls TOTP and uses it for step-up to create a session', async () => {
    const mem = makeMemoryStorage();
    const events: any[] = [];
    const now = new Date('2025-01-01T00:00:00.000Z');
    let tick = 0;
    const core = createAuthCore({
      storage: mem.storage,
      clock: { now: () => new Date(now.getTime() + tick) },
      randomBytes: n => new Uint8Array(n).fill(7),
      totpEncryptionKey: 'k',
      onAuthAttempt: e => {
        events.push(e);
      },
      policy: {
        totp: { issuer: 'Example', digits: 6, periodSeconds: 30, allowedSkewSteps: 1 }
      } as any
    });

    const start = await core.startTotpEnrollment({
      userId: 'u1' as any,
      accountName: 'a@example.com'
    });
    expect(start.secretBase32.length).toBeGreaterThan(10);
    expect(start.otpauthUri).toContain('otpauth://totp/');

    // Generate a valid code for now
    const code = totpCode(start.secretBase32, new Date(now.getTime() + tick), 6, 30);
    await core.finishTotpEnrollment({ userId: 'u1' as any, code });

    // Now password login should require 2FA if TOTP is enabled
    tick += 60_000;

    // Simulate step-up token by creating a challenge (normally created after primary factor).
    const pending = 'pending-1' as any;
    await mem.storage.challenges.createChallenge({
      id: pending,
      type: 'totp_pending',
      userId: 'u1' as any,
      challenge: '',
      expiresAt: new Date(now.getTime() + 5 * 60_000)
    });

    const code2 = totpCode(start.secretBase32, new Date(now.getTime() + tick), 6, 30);
    const out = await core.verifyTotp({ pendingToken: pending, code: code2 });
    expect(out.userId).toBe('u1');
    expect(out.session.sessionToken).toBeTruthy();
    expect(events.some(e => e.type === 'totp_verify' && e.ok === true)).toBe(true);
  });

  it('rejects concurrent replay of the same TOTP step when storage supports atomic step updates', async () => {
    const mem = makeMemoryStorage();
    const base = new Date('2025-01-01T00:00:00.000Z');
    let tick = 0;
    const core = createAuthCore({
      storage: mem.storage,
      clock: { now: () => new Date(base.getTime() + tick) },
      randomBytes: n => new Uint8Array(n).fill(7),
      totpEncryptionKey: 'k',
      policy: {
        totp: { issuer: 'Example', digits: 6, periodSeconds: 30, allowedSkewSteps: 1 }
      } as any
    });

    const start = await core.startTotpEnrollment({
      userId: 'u1' as any,
      accountName: 'a@example.com'
    });
    const codeEnroll = totpCode(start.secretBase32, new Date(base.getTime() + tick), 6, 30);
    await core.finishTotpEnrollment({ userId: 'u1' as any, code: codeEnroll });

    // Move to the next step before verifying, so we aren't replaying the enrollment step.
    tick += 30_000;
    const code = totpCode(start.secretBase32, new Date(base.getTime() + tick), 6, 30);

    const p1 = 'pending-1' as any;
    const p2 = 'pending-2' as any;
    await mem.storage.challenges.createChallenge({
      id: p1,
      type: 'totp_pending',
      userId: 'u1' as any,
      challenge: '',
      expiresAt: new Date(base.getTime() + tick + 5 * 60_000)
    });
    await mem.storage.challenges.createChallenge({
      id: p2,
      type: 'totp_pending',
      userId: 'u1' as any,
      challenge: '',
      expiresAt: new Date(base.getTime() + tick + 5 * 60_000)
    });

    const ok = await core.verifyTotp({ pendingToken: p1, code });
    expect(ok.userId).toBe('u1');

    await expect(core.verifyTotp({ pendingToken: p2, code })).rejects.toMatchObject({
      code: 'totp_invalid',
      status: 401
    });
  });

  it('supports TOTP encryption key rotation via key ids (v2) and can still decrypt legacy v1 secrets', async () => {
    // We want to validate two things:
    // 1) new enrollments use v2.<kid>.{iv}.{tag}.{ct} when a key ring is provided
    // 2) a key ring can decrypt existing legacy v1 ciphertexts (no kid) by trying all keys
    const mem = makeMemoryStorage();
    const base = new Date('2025-01-01T00:00:00.000Z');
    let tick = 0;

    // Phase 1: legacy deployment encrypts v1 secrets with a single key.
    const legacy = createAuthCore({
      storage: mem.storage,
      clock: { now: () => new Date(base.getTime() + tick) },
      randomBytes: n => new Uint8Array(n).fill(7),
      totpEncryptionKey: 'legacy-key',
      policy: {
        totp: { issuer: 'Example', digits: 6, periodSeconds: 30, allowedSkewSteps: 1 }
      } as any
    });

    const startLegacy = await legacy.startTotpEnrollment({
      userId: 'u1' as any,
      accountName: 'a@example.com'
    });
    const codeLegacy = totpCode(startLegacy.secretBase32, new Date(base.getTime() + tick), 6, 30);
    await legacy.finishTotpEnrollment({ userId: 'u1' as any, code: codeLegacy });

    const legacyEncrypted = mem.enabled.get('u1' as any)?.encryptedSecret as string;
    expect(legacyEncrypted.startsWith('v2.')).toBe(false);

    // Phase 2: rotated deployment uses key ring. It must still decrypt the v1 secret.
    const rotated = createAuthCore({
      storage: mem.storage,
      clock: { now: () => new Date(base.getTime() + tick) },
      randomBytes: n => new Uint8Array(n).fill(7),
      totpEncryptionKey: {
        primaryKeyId: 'k2',
        keys: { k1: 'legacy-key', k2: 'new-key' }
      },
      policy: {
        totp: { issuer: 'Example', digits: 6, periodSeconds: 30, allowedSkewSteps: 1 }
      } as any
    });

    tick += 30_000;
    const p = 'pending-rot' as any;
    await mem.storage.challenges.createChallenge({
      id: p,
      type: 'totp_pending',
      userId: 'u1' as any,
      challenge: '',
      expiresAt: new Date(base.getTime() + tick + 5 * 60_000)
    });
    const codeStep = totpCode(startLegacy.secretBase32, new Date(base.getTime() + tick), 6, 30);
    const out = await rotated.verifyTotp({ pendingToken: p, code: codeStep });
    expect(out.userId).toBe('u1');

    // New enrollments (new user) should encrypt as v2 with kid.
    const startV2 = await rotated.startTotpEnrollment({
      userId: 'u2' as any,
      accountName: 'b@example.com'
    });
    void startV2;
    const pendingV2 = await mem.storage.totp.getPending('u2' as any);
    expect(pendingV2?.encryptedSecret.startsWith('v2.k2.')).toBe(true);
  });
});

function totpCode(secretBase32: string, now: Date, digits: number, periodSeconds: number): string {
  const secret = base32Decode(secretBase32);
  const step = Math.floor(now.getTime() / 1000 / periodSeconds);
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(step));
  const hmac = createHmac('sha1', secret).update(buf).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const code =
    ((hmac[offset] & 0x7f) << 24) |
    (hmac[offset + 1] << 16) |
    (hmac[offset + 2] << 8) |
    hmac[offset + 3];
  const mod = 10 ** digits;
  return String(code % mod).padStart(digits, '0');
}

function base32Decode(base32: string): Uint8Array {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const cleaned = base32.replaceAll('=', '').toUpperCase();
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const c of cleaned) {
    const idx = alphabet.indexOf(c);
    if (idx === -1) throw new Error('bad base32');
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return new Uint8Array(out);
}
