import { describe, expect, it } from "vitest";
import { createAuthCore } from "../../../src/core/create-auth-core.js";
import type { AuthStorage, PasswordCredentialRecord, SessionRecord } from "../../../src/core/storage/auth-storage.js";

function makeMemoryStorage(): {
  storage: AuthStorage;
  usersByIdentifier: Map<string, string>;
  passwordByUserId: Map<string, PasswordCredentialRecord>;
  sessionsByHash: Map<string, SessionRecord>;
} {
  const usersByIdentifier = new Map<string, string>();
  const passwordByUserId = new Map<string, PasswordCredentialRecord>();
  const sessionsByHash = new Map<string, SessionRecord>();

  const storage: AuthStorage = {
    users: {
      getUserIdByIdentifier: async (identifier) => usersByIdentifier.get(identifier) ?? null,
      createUser: async (identifier) => {
        if (usersByIdentifier.has(identifier)) throw new Error("conflict");
        const id = `u_${usersByIdentifier.size + 1}`;
        usersByIdentifier.set(identifier, id);
        return id as any;
      },
    },
    passwordCredentials: {
      getForUser: async (userId) => passwordByUserId.get(userId as any) ?? null,
      upsertForUser: async (record) => {
        passwordByUserId.set(record.userId as any, record);
      },
    },
    challenges: {
      createChallenge: async () => undefined,
      consumeChallenge: async () => null,
    },
    totp: {
      getEnabled: async () => null,
      getPending: async () => null,
      setPending: async () => undefined,
      enableFromPending: async () => undefined,
      disable: async () => undefined,
      updateLastUsedAt: async () => undefined,
    },
    sessions: {
      createSession: async (session) => {
        sessionsByHash.set(session.tokenHash as any, session);
      },
      getSessionByTokenHash: async (tokenHash) => sessionsByHash.get(tokenHash as any) ?? null,
      touchSession: async (tokenHash, lastSeenAt) => {
        const s = sessionsByHash.get(tokenHash as any);
        if (s && !s.revokedAt) s.lastSeenAt = lastSeenAt;
      },
      revokeSession: async (tokenHash, revokedAt) => {
        const s = sessionsByHash.get(tokenHash as any);
        if (s) s.revokedAt = revokedAt;
      },
      revokeAllUserSessions: async (userId, revokedAt) => {
        for (const s of sessionsByHash.values()) {
          if (s.userId === userId) s.revokedAt = revokedAt;
        }
      },
      rotateSession: async (oldTokenHash, newSession, revokedAt) => {
        const old = sessionsByHash.get(oldTokenHash as any);
        if (old) old.revokedAt = revokedAt;
        sessionsByHash.set(newSession.tokenHash as any, newSession);
      },
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
  };

  return { storage, usersByIdentifier, passwordByUserId, sessionsByHash };
}

describe("core/password/password-auth", () => {
  it("registers a user and creates a session", async () => {
    const mem = makeMemoryStorage();
    const core = createAuthCore({ storage: mem.storage });

    const res = await core.registerPassword({ identifier: "a@example.com", password: "long-enough-password" });
    expect(res.userId).toBeTruthy();
    expect(res.session.sessionToken).toBeTruthy();
    expect(mem.passwordByUserId.size).toBe(1);
    expect(mem.sessionsByHash.size).toBe(1);
  });

  it("does not enumerate: wrong password and unknown user both fail with password_invalid", async () => {
    const mem = makeMemoryStorage();
    const core = createAuthCore({ storage: mem.storage });
    await core.registerPassword({ identifier: "a@example.com", password: "long-enough-password" });

    await expect(core.loginPassword({ identifier: "a@example.com", password: "wrong-password-here" })).rejects.toMatchObject({
      code: "password_invalid",
    });
    await expect(core.loginPassword({ identifier: "missing@example.com", password: "wrong-password-here" })).rejects.toMatchObject({
      code: "password_invalid",
    });
  });

  it("rehashes (upgrades) when desired params are stronger", async () => {
    const mem = makeMemoryStorage();
    const coreWeak = createAuthCore({ storage: mem.storage, passwordHashParams: { memoryCost: 8192 } });
    await coreWeak.registerPassword({ identifier: "a@example.com", password: "long-enough-password" });

    const before = [...mem.passwordByUserId.values()][0]!;
    expect(before.passwordHash).toContain("m=8192");

    const coreStrong = createAuthCore({ storage: mem.storage, passwordHashParams: { memoryCost: 16384 } });
    await coreStrong.loginPassword({ identifier: "a@example.com", password: "long-enough-password" });

    const after = [...mem.passwordByUserId.values()][0]!;
    expect(after.passwordHash).toContain("m=16384");
  });

  it("invokes onAuthAttempt hook", async () => {
    const mem = makeMemoryStorage();
    const events: any[] = [];
    const core = createAuthCore({
      storage: mem.storage,
      onAuthAttempt: (e) => events.push(e),
    });

    await core.registerPassword({ identifier: "a@example.com", password: "long-enough-password" });
    await expect(core.loginPassword({ identifier: "a@example.com", password: "wrong-password-here" })).rejects.toBeTruthy();
    await core.loginPassword({ identifier: "a@example.com", password: "long-enough-password" });

    expect(events.some((e) => e.type === "password_register" && e.ok === true)).toBe(true);
    expect(events.some((e) => e.type === "password_login" && e.ok === false)).toBe(true);
    expect(events.some((e) => e.type === "password_login" && e.ok === true)).toBe(true);
  });
});


