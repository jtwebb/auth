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
      keys: e => (e.type === 'password_login' ? [`id:${e.identifier}`] : [])
    });

    // Record failures via onAuthAttempt (non-blocking)
    rl.onAuthAttempt({
      type: 'password_login',
      identifier: 'a@example.com',
      ok: false,
      reason: 'invalid_password'
    });
    rl.onAuthAttempt({
      type: 'password_login',
      identifier: 'a@example.com',
      ok: false,
      reason: 'invalid_password'
    });

    expect(() => rl.assertAllowed(['id:a@example.com'])).toThrow(AuthError);
    expect(() => rl.assertAllowed(['id:a@example.com'])).toThrow(/Too many attempts/);
  });
});
