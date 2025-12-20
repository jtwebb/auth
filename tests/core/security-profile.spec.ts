import { describe, expect, it } from 'vitest';
import { createAuthCore } from '../../src/core/create-auth-core.js';
import type { AuthStorage } from '../../src/core/storage/auth-storage.js';

function minimalStorage(): AuthStorage {
  return {
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
      replaceCodes: async () => undefined,
      consumeCode: async () => false,
      countRemaining: async () => 0
    }
  };
}

describe('core/securityProfile', () => {
  it('strict uses passkey UV required and shorter session defaults', () => {
    const core = createAuthCore({ storage: minimalStorage(), securityProfile: 'strict' });
    expect(core.policy.passkey.userVerification).toBe('required');
    expect(core.policy.session.absoluteTtlMs).toBeLessThan(1000 * 60 * 60 * 24 * 30);
  });

  it('legacy relaxes password length and disables session rotation by default', () => {
    const core = createAuthCore({ storage: minimalStorage(), securityProfile: 'legacy' });
    expect(core.policy.password.minLength).toBe(8);
    expect(core.policy.session.rotateEveryMs).toBeUndefined();
    expect(core.policy.session.idleTtlMs).toBeUndefined();
  });
});
