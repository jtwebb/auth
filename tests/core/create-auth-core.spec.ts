import { describe, expect, it } from "vitest";
import { AuthError, createAuthCore } from "../../src/core/index.js";

const noopStorage = {
  users: {
    getUserIdByIdentifier: async () => null,
    createUser: async () => "user-1",
  },
  passwordCredentials: {
    getForUser: async () => null,
    upsertForUser: async () => undefined,
  },
  challenges: {
    createChallenge: async () => undefined,
    consumeChallenge: async () => null,
  },
  sessions: {
    createSession: async () => undefined,
    getSessionByTokenHash: async () => null,
    touchSession: async () => undefined,
    revokeSession: async () => undefined,
    revokeAllUserSessions: async () => undefined,
    rotateSession: async () => undefined,
  },
  webauthn: {
    listCredentialsForUser: async () => [],
    getCredentialById: async () => null,
    createCredential: async () => undefined,
    updateCredentialCounter: async () => undefined,
  },
  backupCodes: {
    replaceCodes: async () => undefined,
    consumeCode: async () => false,
    countRemaining: async () => 0,
  },
} as const;

describe("core/create-auth-core", () => {
  it("requires a storage implementation", () => {
    expect(() => createAuthCore({} as any)).toThrow(AuthError);
  });

  it("creates session tokens and hashes them deterministically", () => {
    const core = createAuthCore({
      storage: noopStorage as any,
      randomBytes: (n) => new Uint8Array(n).fill(7),
    });

    const { sessionToken, sessionTokenHash } = core.createSessionToken();
    expect(typeof sessionToken).toBe("string");
    expect(sessionToken.length).toBeGreaterThan(10);
    expect(typeof sessionTokenHash).toBe("string");
    expect(sessionTokenHash).toMatch(/^[a-f0-9]{64}$/);

    const hash2 = core.hashSessionToken(sessionToken);
    expect(hash2).toBe(sessionTokenHash);
  });

  it("uses HMAC when sessionTokenHashSecret is provided", () => {
    const coreA = createAuthCore({
      storage: noopStorage as any,
      sessionTokenHashSecret: "secret-a",
    });
    const coreB = createAuthCore({
      storage: noopStorage as any,
      sessionTokenHashSecret: "secret-b",
    });

    const token = coreA.createSessionToken().sessionToken;
    expect(coreA.hashSessionToken(token)).not.toBe(coreB.hashSessionToken(token));
  });

  it("rotateBackupCodes is implemented and returns plaintext codes (display-once)", async () => {
    const core = createAuthCore({
      storage: noopStorage as any,
      randomBytes: (n) => new Uint8Array(n).fill(1),
    });

    const res = await core.rotateBackupCodes({ userId: "u1" as any });
    expect(res.userId).toBe("u1");
    expect(Array.isArray(res.codes)).toBe(true);
    expect(res.codes.length).toBeGreaterThan(0);
  });
});


