import { describe, expect, it, vi } from 'vitest';
import { createAuthCore } from '../../../src/core/create-auth-core.js';
import type {
  AuthStorage,
  SessionRecord,
  StoredChallenge,
  WebAuthnCredentialRecord
} from '../../../src/core/storage/auth-storage.js';

vi.mock('@simplewebauthn/server', async () => {
  const actual = await vi.importActual<any>('@simplewebauthn/server');
  return {
    ...actual,
    generateRegistrationOptions: vi.fn(async (opts: any) => ({
      rp: { name: opts.rpName, id: opts.rpID },
      user: { id: 'userhandle', name: opts.userName, displayName: opts.userDisplayName ?? '' },
      challenge: 'challenge-reg',
      pubKeyCredParams: []
    })),
    verifyRegistrationResponse: vi.fn(async () => ({
      verified: true,
      registrationInfo: {
        fmt: 'none',
        aaguid: '00000000-0000-0000-0000-000000000000',
        credential: {
          id: 'cred-1',
          publicKey: new Uint8Array([1, 2, 3]),
          counter: 0,
          transports: ['internal']
        },
        credentialType: 'public-key',
        attestationObject: new Uint8Array([9]),
        userVerified: true,
        credentialDeviceType: 'singleDevice',
        credentialBackedUp: false,
        origin: 'https://example.com',
        rpID: 'example.com'
      }
    })),
    generateAuthenticationOptions: vi.fn(async () => ({
      challenge: 'challenge-auth',
      rpId: 'example.com',
      userVerification: 'preferred'
    })),
    verifyAuthenticationResponse: vi.fn(async () => ({
      verified: true,
      authenticationInfo: {
        credentialID: 'cred-1',
        newCounter: 2,
        userVerified: true,
        credentialDeviceType: 'singleDevice',
        credentialBackedUp: false,
        origin: 'https://example.com',
        rpID: 'example.com'
      }
    }))
  };
});

function makeMemoryStorage() {
  const challenges = new Map<string, StoredChallenge>();
  const sessions = new Map<string, SessionRecord>();
  const credentials = new Map<string, WebAuthnCredentialRecord>();

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
      revokeSession: async () => undefined,
      revokeAllUserSessions: async () => undefined,
      rotateSession: async () => undefined
    },
    webauthn: {
      listCredentialsForUser: async userId =>
        [...credentials.values()].filter(c => c.userId === userId),
      getCredentialById: async id => credentials.get(id as any) ?? null,
      createCredential: async rec => {
        credentials.set(rec.id as any, rec);
      },
      updateCredentialCounter: async (id, counter, updatedAt) => {
        const c = credentials.get(id as any);
        if (c) {
          c.counter = counter;
          c.updatedAt = updatedAt;
        }
      }
    },
    backupCodes: {
      replaceCodes: async () => undefined,
      consumeCode: async () => false,
      countRemaining: async () => 0
    }
  };

  return { storage, challenges, sessions, credentials };
}

describe('core/passkey/passkey-auth', () => {
  it('startPasskeyLogin stores a single-use challenge and returns options', async () => {
    const mem = makeMemoryStorage();
    const core = createAuthCore({
      storage: mem.storage,
      policy: {
        passkey: {
          rpId: 'example.com',
          rpName: 'Example',
          origins: ['https://example.com']
        } as any
      },
      randomBytes: n => new Uint8Array(n).fill(1)
    });

    const res = await core.startPasskeyLogin({});
    expect(res.challengeId).toBeTruthy();
    expect(res.options.challenge).toBe('challenge-auth');
    expect(mem.challenges.size).toBe(1);
  });

  it('finishPasskeyRegistration persists a credential', async () => {
    const mem = makeMemoryStorage();
    const core = createAuthCore({
      storage: mem.storage,
      policy: {
        passkey: {
          rpId: 'example.com',
          rpName: 'Example',
          origins: ['https://example.com'],
          userVerification: 'preferred'
        } as any
      },
      randomBytes: n => new Uint8Array(n).fill(2)
    });

    const start = await core.startPasskeyRegistration({
      userId: 'u1' as any,
      userName: 'a@example.com'
    });
    const finish = await core.finishPasskeyRegistration({
      userId: 'u1' as any,
      challengeId: start.challengeId,
      response: { id: 'cred-1' } as any
    });

    expect(finish.credentialId).toBeTruthy();
    expect(mem.credentials.size).toBe(1);
  });

  it('finishPasskeyLogin creates a session and updates the counter', async () => {
    const mem = makeMemoryStorage();
    const events: any[] = [];
    // Seed credential
    mem.credentials.set('cred-1', {
      id: 'cred-1' as any,
      userId: 'u1' as any,
      credentialId: 'cred-1',
      publicKey: new Uint8Array([1, 2, 3]),
      counter: 0,
      createdAt: new Date()
    });

    const core = createAuthCore({
      storage: mem.storage,
      onAuthAttempt: e => {
        events.push(e);
      },
      policy: {
        passkey: {
          rpId: 'example.com',
          rpName: 'Example',
          origins: ['https://example.com'],
          userVerification: 'preferred'
        } as any
      },
      randomBytes: n => new Uint8Array(n).fill(3)
    });

    const start = await core.startPasskeyLogin({});
    const finish = await core.finishPasskeyLogin({
      challengeId: start.challengeId,
      response: { id: 'cred-1' } as any
    });

    expect(finish.userId).toBe('u1');
    expect(mem.sessions.size).toBe(1);
    expect(mem.credentials.get('cred-1')?.counter).toBe(2);
    expect(events.some(e => e.type === 'passkey_login_finish' && e.ok === true)).toBe(true);
  });
});
