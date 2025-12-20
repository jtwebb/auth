import { describe, expect, it } from 'vitest';
import { AuthError } from '../../src/core/auth-error.js';
import { InMemoryRateLimiter, createOnAuthAttemptRateLimiter } from '../../src/core/rate-limit.js';

describe('core/rate-limit', () => {
  it('blocks after max within window and unblocks after window resets', () => {
    let now = 0;
    const limiter = new InMemoryRateLimiter({ nowMs: () => now });
    const rule = { windowMs: 1000, max: 2 };

    expect(limiter.consume('k', rule)).toEqual({ ok: true });
    expect(limiter.consume('k', rule)).toEqual({ ok: true });
    const third = limiter.consume('k', rule);
    expect(third.ok).toBe(false);

    now += 1000;
    expect(limiter.consume('k', rule)).toEqual({ ok: true });
  });

  it('creates a non-blocking onAuthAttempt handler + a blocking assertAllowed()', async () => {
    let now = 0;
    const limiter = new InMemoryRateLimiter({ nowMs: () => now });
    const rl = createOnAuthAttemptRateLimiter({
      limiter,
      rule: { windowMs: 10_000, max: 2 },
      keys: e => (e.type === 'password_login' ? [`id:${e.identifierHash}`] : [])
    });

    // Record failures via onAuthAttempt (non-blocking)
    rl.onAuthAttempt({
      type: 'password_login',
      identifierHash: 'h1',
      ok: false,
      reason: 'invalid_password'
    });
    rl.onAuthAttempt({
      type: 'password_login',
      identifierHash: 'h1',
      ok: false,
      reason: 'invalid_password'
    });

    expect(() => rl.assertAllowed(['id:h1'])).toThrow(AuthError);
    expect(() => rl.assertAllowed(['id:h1'])).toThrow(/Too many attempts/);
  });

  it('prunes expired buckets (best-effort memory cleanup)', () => {
    let now = 0;
    const limiter = new InMemoryRateLimiter({ nowMs: () => now, pruneEvery: 10_000 });
    const rule = { windowMs: 1000, max: 2 };

    expect(limiter.consume('k1', rule)).toEqual({ ok: true });
    now += 1001;
    expect(limiter.pruneExpired()).toBe(1);
  });
});
