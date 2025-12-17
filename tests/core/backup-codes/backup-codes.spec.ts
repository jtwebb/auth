import { describe, expect, it } from 'vitest';
import { createAuthCore } from '../../../src/core/create-auth-core.js';
import type { AuthStorage, BackupCodeRecord } from '../../../src/core/storage/auth-storage.js';

function makeMemoryStorage() {
  const codesByUser = new Map<string, BackupCodeRecord[]>();

  const storage: AuthStorage = {
    users: {
      getUserIdByIdentifier: async () => null,
      createUser: async () => 'u1' as any
    },
    passwordCredentials: {
      getForUser: async () => null,
      upsertForUser: async () => undefined
    },
    challenges: {
      createChallenge: async () => undefined,
      consumeChallenge: async () => null
    },
    totp: {
      getEnabled: async () => null,
      getPending: async () => null,
      setPending: async () => undefined,
      enableFromPending: async () => undefined,
      disable: async () => undefined,
      updateLastUsedAt: async () => undefined
    },
    sessions: {
      createSession: async () => undefined,
      getSessionByTokenHash: async () => null,
      touchSession: async () => undefined,
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
      replaceCodes: async (userId, codes) => {
        codesByUser.set(userId as any, codes);
      },
      consumeCode: async (userId, codeHash, consumedAt) => {
        const list = codesByUser.get(userId as any) ?? [];
        const rec = list.find(c => c.codeHash === codeHash && !c.consumedAt);
        if (!rec) return false;
        rec.consumedAt = consumedAt;
        return true;
      },
      countRemaining: async userId => {
        const list = codesByUser.get(userId as any) ?? [];
        return list.filter(c => !c.consumedAt).length;
      }
    }
  };

  return { storage, codesByUser };
}

describe('core/backup-codes', () => {
  it('rotates backup codes and stores only hashes', async () => {
    const mem = makeMemoryStorage();
    const core = createAuthCore({
      storage: mem.storage,
      policy: { backupCodes: { count: 3, length: 10 } } as any,
      randomBytes: n => new Uint8Array(n).map((_, i) => i + 1),
      backupCodeHashSecret: 'secret'
    });

    const res = await core.rotateBackupCodes({ userId: 'u1' as any });
    expect(res.codes).toHaveLength(3);
    expect(res.codes[0]).toContain('-');

    const stored = mem.codesByUser.get('u1')!;
    expect(stored).toHaveLength(3);
    for (const rec of stored) {
      expect(rec.codeHash).toMatch(/^[a-f0-9]{64}$/);
      // Ensure we didn't accidentally store plaintext
      expect(res.codes).not.toContain(rec.codeHash);
    }
  });

  it('redeems a backup code exactly once (normalized input)', async () => {
    const mem = makeMemoryStorage();
    const core = createAuthCore({
      storage: mem.storage,
      policy: { backupCodes: { count: 1, length: 10 } } as any,
      randomBytes: n => new Uint8Array(n).fill(7),
      backupCodeHashSecret: 'secret'
    });

    const rotated = await core.rotateBackupCodes({ userId: 'u1' as any });
    const code = rotated.codes[0]!;
    const messy = code.replaceAll('-', ' ').toLowerCase();

    const redeemed = await core.redeemBackupCode({ userId: 'u1' as any, code: messy });
    expect(redeemed.remaining).toBe(0);

    await expect(core.redeemBackupCode({ userId: 'u1' as any, code })).rejects.toMatchObject({
      code: 'backup_code_invalid'
    });
  });

  it('rotation invalidates old codes', async () => {
    const mem = makeMemoryStorage();
    let seed = 0;
    const core = createAuthCore({
      storage: mem.storage,
      policy: { backupCodes: { count: 1, length: 10 } } as any,
      // Ensure a second rotation generates a *different* code than the first rotation
      randomBytes: n => new Uint8Array(n).fill(++seed),
      backupCodeHashSecret: 'secret'
    });

    const first = await core.rotateBackupCodes({ userId: 'u1' as any });
    const oldCode = first.codes[0]!;

    // New rotation should replace the old list
    await core.rotateBackupCodes({ userId: 'u1' as any });

    await expect(
      core.redeemBackupCode({ userId: 'u1' as any, code: oldCode })
    ).rejects.toMatchObject({
      code: 'backup_code_invalid'
    });
  });
});
