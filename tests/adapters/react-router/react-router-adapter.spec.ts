import { describe, expect, it } from 'vitest';
import { createAuthCore } from '../../../src/core/create-auth-core.js';
import type { AuthStorage, SessionRecord } from '../../../src/core/storage/auth-storage.js';
import { createReactRouterAuthAdapter } from '../../../src/adapters/react-router/react-router-adapter.js';
import { AuthError } from '../../../src/core/auth-error.js';
import { InMemoryProgressiveDelay, InMemoryRateLimiter } from '../../../src/core/rate-limit.js';

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
      revokeAllUserSessions: async () => undefined,
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

describe('adapters/react-router/react-router-adapter', () => {
  it('adds Set-Cookie when session rotates during validate()', async () => {
    const mem = makeMemoryStorage();
    const t0 = new Date('2025-01-01T00:00:00.000Z');
    let now = t0;

    const core = createAuthCore({
      storage: mem.storage,
      clock: { now: () => now },
      randomBytes: n => new Uint8Array(n).fill(1),
      policy: { session: { rotateEveryMs: 1, absoluteTtlMs: 1000 * 60 * 60 } } as any
    });

    const tok = core.createSessionToken();
    const h = core.hashSessionToken(tok.sessionToken);
    await mem.storage.sessions.createSession({
      tokenHash: h,
      userId: 'u1' as any,
      createdAt: t0,
      lastSeenAt: t0,
      expiresAt: new Date(t0.getTime() + 1000 * 60 * 60)
    });

    const adapter = createReactRouterAuthAdapter({
      core,
      sessionCookie: { name: 'sid', path: '/', httpOnly: true, secure: true, sameSite: 'lax' },
      csrf: { enabled: false }
    });

    now = new Date(t0.getTime() + 10);
    const req = new Request('https://example.com', {
      headers: { cookie: `sid=${tok.sessionToken as any}` }
    });
    const { result, headers } = await adapter.validate(req);
    expect(result.ok).toBe(true);
    expect(headers.get('set-cookie')).toMatch(/sid=/);
  });

  it('requires Origin/Referer by default for state-changing actions (CSRF hardening)', async () => {
    const core = {
      policy: { passkey: { origins: ['https://example.com'] } },
      validateSession: async () => ({ ok: false, reason: 'missing' })
    } as any;

    const adapter = createReactRouterAuthAdapter({
      core,
      sessionCookie: { name: 'sid', path: '/', httpOnly: true, secure: true, sameSite: 'lax' }
    });

    const req = new Request('https://example.com/login', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ identifier: 'a', password: 'b' })
    });

    await expect(adapter.actions.passwordLogin(req)).rejects.toMatchObject({
      code: 'forbidden',
      status: 403
    });
  });

  it('derives userId from session (ignores client userId) for authenticated enrollment flows', async () => {
    let finishUserId: string | null = null;

    const core = {
      policy: { passkey: { origins: ['https://example.com'] } },
      validateSession: async () => ({ ok: true, userId: 'u_session' }),
      finishTotpEnrollment: async (input: any) => {
        finishUserId = input.userId as any;
        return { enabled: true };
      }
    } as any;

    const adapter = createReactRouterAuthAdapter({
      core,
      sessionCookie: { name: 'sid', path: '/', httpOnly: true, secure: true, sameSite: 'lax' },
      csrf: { enabled: false }
    });

    const req = new Request('https://example.com/totp/finish', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        cookie: 'sid=abc'
      },
      body: JSON.stringify({ userId: 'u_attacker', code: '123456' })
    });

    const res = await adapter.actions.totpEnrollmentFinish(req);
    expect(res.status).toBe(302);
    expect(finishUserId).toBe('u_session');
  });

  it('propagates rotation headers from requireUser() into action responses', async () => {
    const core = {
      policy: { passkey: { origins: ['https://example.com'] } },
      validateSession: async () => ({
        ok: true,
        userId: 'u1',
        rotatedSession: { sessionToken: 'newtok', sessionTokenHash: 'h' }
      }),
      startTotpEnrollment: async () => ({ userId: 'u1', secretBase32: 'S', otpauthUri: 'otpauth' })
    } as any;

    const adapter = createReactRouterAuthAdapter({
      core,
      sessionCookie: { name: 'sid', path: '/', httpOnly: true, secure: true, sameSite: 'lax' },
      csrf: { enabled: false }
    });

    const req = new Request('https://example.com/totp/start', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        cookie: 'sid=oldtok'
      },
      body: JSON.stringify({ accountName: 'acct' })
    });

    const res = await adapter.actions.totpEnrollmentStart(req);
    expect(res.headers.get('set-cookie')).toMatch(/sid=newtok/);
  });

  it('rate limits passwordLogin by identifier by default (429 + Retry-After)', async () => {
    let nowMs = 0;
    const limiter = new InMemoryRateLimiter({ nowMs: () => nowMs });
    let calls = 0;
    const core = {
      policy: { passkey: { origins: ['https://example.com'] } },
      loginPassword: async () => {
        calls++;
        throw new Error('should not be called after rate limit triggers');
      }
    } as any;

    const adapter = createReactRouterAuthAdapter({
      core,
      sessionCookie: { name: 'sid', path: '/', httpOnly: true, secure: true, sameSite: 'lax' },
      csrf: { enabled: false },
      rateLimit: {
        limiter,
        rules: { passwordLoginPerIdentifier: { windowMs: 60_000, max: 1 } },
        getClientId: () => null
      }
    });

    const mkReq = () =>
      new Request('https://example.com/login', {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ identifier: 'a@example.com', password: 'pw' })
      });

    // First attempt passes the limiter and calls core (which throws)
    await expect(adapter.actions.passwordLogin(mkReq())).resolves.toMatchObject({ status: 500 });
    expect(calls).toBe(1);

    // Second attempt is blocked by rate limiter; should return 429 + Retry-After
    const res2 = await adapter.actions.passwordLogin(mkReq());
    expect(res2.status).toBe(429);
    expect(res2.headers.get('retry-after')).toBeTruthy();
  });

  it('applies progressive delays/lockouts on failures and resets on success', async () => {
    let nowMs = 0;
    const limiter = new InMemoryRateLimiter({ nowMs: () => nowMs });
    const store = new InMemoryProgressiveDelay({ nowMs: () => nowMs });

    let attempt = 0;
    const core = {
      policy: { passkey: { origins: ['https://example.com'] } },
      loginPassword: async () => {
        attempt++;
        if (attempt === 3) {
          // success clears penalties
          return { userId: 'u1', session: { sessionToken: 't', sessionTokenHash: 'h' } };
        }
        throw new AuthError('password_invalid', 'Invalid credentials', {
          publicMessage: 'Invalid credentials',
          status: 401
        });
      }
    } as any;

    const adapter = createReactRouterAuthAdapter({
      core,
      sessionCookie: { name: 'sid', path: '/', httpOnly: true, secure: true, sameSite: 'lax' },
      csrf: { enabled: false },
      rateLimit: {
        limiter,
        // Disable fixed-window blocking so the test isolates progressive behavior.
        rules: { passwordLoginPerIdentifier: { windowMs: 60_000, max: 1000 } },
        getClientId: () => null,
        progressiveDelay: {
          store,
          rules: {
            passwordLoginPerIdentifier: {
              failureWindowMs: 60_000,
              startAfterFailures: 1,
              baseDelayMs: 10_000,
              factor: 1,
              maxDelayMs: 10_000,
              lockoutAfterFailures: 2,
              lockoutMs: 60_000
            }
          }
        }
      }
    });

    const mkReq = () =>
      new Request('https://example.com/login', {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ identifier: 'a@example.com', password: 'pw' })
      });

    // 1st failure: returns 401, but now future attempts are delayed
    const r1 = await adapter.actions.passwordLogin(mkReq());
    expect(r1.status).toBe(401);

    // Immediately retry: blocked (429)
    const r2 = await adapter.actions.passwordLogin(mkReq());
    expect(r2.status).toBe(429);
    expect(r2.headers.get('retry-after')).toBeTruthy();

    // Advance time beyond delay to allow another real attempt (2nd failure triggers lockout)
    nowMs += 10_000;
    const r3 = await adapter.actions.passwordLogin(mkReq());
    expect(r3.status).toBe(401);

    // Immediately retry: blocked by lockout
    const r4 = await adapter.actions.passwordLogin(mkReq());
    expect(r4.status).toBe(429);

    // Advance time beyond lockout: next attempt succeeds and resets
    nowMs += 60_000;
    const r5 = await adapter.actions.passwordLogin(mkReq());
    expect(r5.status).toBe(302);

    // Immediate retry after success: should be allowed (reset) and return 401 (not 429)
    const r6 = await adapter.actions.passwordLogin(mkReq());
    expect(r6.status).toBe(401);
  });
});
