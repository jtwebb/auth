import { describe, expect, it } from "vitest";
import { createAuthCore } from "../../../src/core/create-auth-core.js";
import type { AuthStorage, SessionRecord } from "../../../src/core/storage/auth-storage.js";
import { createReactRouterAuthAdapter } from "../../../src/adapters/react-router/react-router-adapter.js";

function makeMemoryStorage() {
  const sessions = new Map<string, SessionRecord>();

  const storage: AuthStorage = {
    users: { getUserIdByIdentifier: async () => null, createUser: async () => "u1" as any },
    passwordCredentials: { getForUser: async () => null, upsertForUser: async () => undefined },
    challenges: { createChallenge: async () => undefined, consumeChallenge: async () => null },
    totp: {
      getEnabled: async () => null,
      getPending: async () => null,
      setPending: async () => undefined,
      enableFromPending: async () => undefined,
      disable: async () => undefined,
      updateLastUsedAt: async () => undefined,
    },
    sessions: {
      createSession: async (s) => sessions.set(s.tokenHash as any, s),
      getSessionByTokenHash: async (h) => sessions.get(h as any) ?? null,
      touchSession: async (h, lastSeenAt) => {
        const s = sessions.get(h as any);
        if (s && !s.revokedAt) s.lastSeenAt = lastSeenAt;
      },
      revokeSession: async (h, revokedAt) => {
        const s = sessions.get(h as any);
        if (s) s.revokedAt = revokedAt;
      },
      revokeAllUserSessions: async () => undefined,
      rotateSession: async (oldHash, newSession, revokedAt) => {
        const old = sessions.get(oldHash as any);
        if (old) old.revokedAt = revokedAt;
        sessions.set(newSession.tokenHash as any, newSession);
      },
    },
    webauthn: {
      listCredentialsForUser: async () => [],
      getCredentialById: async () => null,
      createCredential: async () => undefined,
      updateCredentialCounter: async () => undefined,
    },
    backupCodes: { replaceCodes: async () => undefined, consumeCode: async () => false, countRemaining: async () => 0 },
  };

  return { storage, sessions };
}

describe("adapters/react-router/react-router-adapter", () => {
  it("adds Set-Cookie when session rotates during validate()", async () => {
    const mem = makeMemoryStorage();
    const t0 = new Date("2025-01-01T00:00:00.000Z");
    let now = t0;

    const core = createAuthCore({
      storage: mem.storage,
      clock: { now: () => now },
      randomBytes: (n) => new Uint8Array(n).fill(1),
      policy: { session: { rotateEveryMs: 1, absoluteTtlMs: 1000 * 60 * 60 } } as any,
    });

    const tok = core.createSessionToken();
    const h = core.hashSessionToken(tok.sessionToken);
    await mem.storage.sessions.createSession({
      tokenHash: h,
      userId: "u1" as any,
      createdAt: t0,
      lastSeenAt: t0,
      expiresAt: new Date(t0.getTime() + 1000 * 60 * 60),
    });

    const adapter = createReactRouterAuthAdapter({
      core,
      sessionCookie: { name: "sid", path: "/", httpOnly: true, secure: true, sameSite: "lax" },
      csrf: { enabled: false },
    });

    now = new Date(t0.getTime() + 10);
    const req = new Request("https://example.com", { headers: { cookie: `sid=${tok.sessionToken as any}` } });
    const { result, headers } = await adapter.validate(req);
    expect(result.ok).toBe(true);
    expect(headers.get("set-cookie")).toMatch(/sid=/);
  });
});


