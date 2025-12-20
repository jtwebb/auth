import { AuthError } from './auth-error.js';
import type { AuthAttemptEvent } from './create-auth-core.js';

export type RateLimitRule = {
  /**
   * Fixed window size.
   */
  windowMs: number;
  /**
   * Maximum allowed events within the window.
   */
  max: number;
};

export type RateLimitResult =
  | { ok: true }
  | {
      ok: false;
      /**
       * Milliseconds until the current window resets.
       */
      retryAfterMs: number;
    };

type Bucket = { windowStartMs: number; windowMs: number; count: number };

/**
 * Small in-memory rate limiter.
 *
 * - Fixed-window counting (fast, simple).
 * - Intended as a default/dev utility. For production in multi-instance deployments,
 *   use a shared store (Redis) with atomic increments.
 */
export class InMemoryRateLimiter {
  private readonly buckets = new Map<string, Bucket>();
  private readonly nowMs: () => number;
  private readonly pruneEvery: number;
  private opsSincePrune = 0;

  constructor(options: { nowMs?: () => number; pruneEvery?: number } = {}) {
    this.nowMs = options.nowMs ?? (() => Date.now());
    this.pruneEvery = Math.max(1, Math.floor(options.pruneEvery ?? 1000));
  }

  consume(key: string, rule: RateLimitRule): RateLimitResult {
    if (!key) return { ok: true };
    if (!Number.isFinite(rule.windowMs) || rule.windowMs <= 0)
      throw new AuthError('invalid_input', 'rate limit rule.windowMs must be > 0');
    if (!Number.isFinite(rule.max) || rule.max < 1)
      throw new AuthError('invalid_input', 'rate limit rule.max must be >= 1');

    const now = this.nowMs();
    this.opsSincePrune++;
    if (this.opsSincePrune >= this.pruneEvery) {
      this.opsSincePrune = 0;
      this.pruneExpired(now);
    }
    const existing = this.buckets.get(key);
    const sameWindow =
      existing !== undefined &&
      existing.windowMs === rule.windowMs &&
      now - existing.windowStartMs < rule.windowMs;

    const bucket: Bucket = sameWindow
      ? {
          windowStartMs: existing!.windowStartMs,
          windowMs: rule.windowMs,
          count: existing!.count + 1
        }
      : { windowStartMs: now, windowMs: rule.windowMs, count: 1 };

    this.buckets.set(key, bucket);

    if (bucket.count <= rule.max) return { ok: true };
    const retryAfterMs = Math.max(0, bucket.windowStartMs + rule.windowMs - now);
    return { ok: false, retryAfterMs };
  }

  reset(key: string): void {
    this.buckets.delete(key);
  }

  /**
   * Remove expired buckets to reduce unbounded memory growth under high key cardinality.
   * Returns the number of removed buckets.
   *
   * Note: this class remains a dev/single-instance utility; for production use a shared store.
   */
  pruneExpired(nowMs: number = this.nowMs()): number {
    let removed = 0;
    for (const [k, b] of this.buckets) {
      if (nowMs - b.windowStartMs >= b.windowMs) {
        this.buckets.delete(k);
        removed++;
      }
    }
    return removed;
  }
}

export function toRateLimitedAuthError(retryAfterMs: number): AuthError {
  const seconds = Math.max(1, Math.ceil(retryAfterMs / 1000));
  return new AuthError('rate_limited', 'Too many attempts', {
    status: 429,
    publicMessage: `Too many attempts. Try again in ${seconds} seconds.`
  });
}

export type OnAuthAttemptRateLimiterOptions = {
  limiter: InMemoryRateLimiter;
  /**
   * Which auth attempts should count toward the limit.
   * Most apps want to count failures only.
   */
  count?: 'failures_only' | 'all';
  /**
   * Derive one or more keys from the event (e.g. per-ip and per-identifier).
   * Return an empty list to disable limiting for that event.
   */
  keys: (event: AuthAttemptEvent) => string[];
  /**
   * The fixed-window rule applied per key.
   */
  rule: RateLimitRule;
};

/**
 * Helper to convert `onAuthAttempt` events into rate-limit counters.
 *
 * This does NOT automatically block requests (because `onAuthAttempt` is intentionally
 * non-blocking); instead, call `assertAllowed(keys, rule)` before invoking auth operations.
 */
export function createOnAuthAttemptRateLimiter(options: OnAuthAttemptRateLimiterOptions): {
  onAuthAttempt: (event: AuthAttemptEvent) => void;
  assertAllowed: (keys: string[]) => void;
} {
  const count = options.count ?? 'failures_only';

  const onAuthAttempt = (event: AuthAttemptEvent) => {
    if (count === 'failures_only' && event.ok) return;
    const keys = options.keys(event);
    for (const key of keys) {
      const res = options.limiter.consume(key, options.rule);
      // Note: onAuthAttempt is non-blocking; we intentionally do not throw here.
      // Blocking should happen via assertAllowed() in the calling adapter/app.
      void res;
    }
  };

  const assertAllowed = (keys: string[]) => {
    for (const key of keys) {
      const res = options.limiter.consume(key, options.rule);
      if (!res.ok) throw toRateLimitedAuthError(res.retryAfterMs);
    }
  };

  return { onAuthAttempt, assertAllowed };
}

export type ProgressiveDelayRule = {
  /**
   * If the last failure is older than this, failures "cool off" and the counter resets.
   */
  failureWindowMs: number;
  /**
   * Start applying delay/lockout after this many failures.
   */
  startAfterFailures: number;
  /**
   * Base delay used for backoff (ms).
   */
  baseDelayMs: number;
  /**
   * Exponential factor per failure above startAfterFailures.
   */
  factor: number;
  /**
   * Cap for backoff delay (ms).
   */
  maxDelayMs: number;
  /**
   * After this many failures, enforce a lockout window.
   */
  lockoutAfterFailures: number;
  /**
   * Lockout duration (ms).
   */
  lockoutMs: number;
};

export type ProgressiveDelayStatus =
  | { ok: true }
  | { ok: false; retryAfterMs: number; failures: number; locked: boolean };

type BackoffState = {
  failures: number;
  lastFailureMs: number;
  lockedUntilMs: number;
  nextAllowedAtMs: number;
  /**
   * Best-effort expiry for pruning (max of cooldown window + any lockout/delay).
   */
  expiresAtMs: number;
};

/**
 * In-memory progressive delays + temporary lockouts.
 *
 * - Increases retry delay with consecutive failures.
 * - Resets on success.
 * - Intended for single-instance. For multi-instance, use shared storage.
 */
export class InMemoryProgressiveDelay {
  private readonly state = new Map<string, BackoffState>();
  private readonly nowMs: () => number;
  private readonly pruneEvery: number;
  private opsSincePrune = 0;

  constructor(options: { nowMs?: () => number; pruneEvery?: number } = {}) {
    this.nowMs = options.nowMs ?? (() => Date.now());
    this.pruneEvery = Math.max(1, Math.floor(options.pruneEvery ?? 1000));
  }

  check(key: string): ProgressiveDelayStatus {
    if (!key) return { ok: true };
    const now = this.nowMs();
    const s = this.state.get(key);
    if (!s) return { ok: true };
    if (now >= s.expiresAtMs) {
      this.state.delete(key);
      return { ok: true };
    }
    const until = Math.max(s.lockedUntilMs, s.nextAllowedAtMs);
    if (until <= now) return { ok: true };
    return {
      ok: false,
      retryAfterMs: until - now,
      failures: s.failures,
      locked: s.lockedUntilMs > now
    };
  }

  recordFailure(key: string, rule: ProgressiveDelayRule): ProgressiveDelayStatus {
    if (!key) return { ok: true };
    validateProgressiveRule(rule);
    const now = this.nowMs();
    this.opsSincePrune++;
    if (this.opsSincePrune >= this.pruneEvery) {
      this.opsSincePrune = 0;
      this.pruneExpired(now);
    }

    const prev = this.state.get(key);
    const cooled =
      prev !== undefined && now - prev.lastFailureMs > rule.failureWindowMs ? undefined : prev;

    const failures = (cooled?.failures ?? 0) + 1;
    const lastFailureMs = now;

    let nextAllowedAtMs = now;
    if (failures >= rule.startAfterFailures) {
      const n = failures - rule.startAfterFailures;
      const delay = Math.min(rule.maxDelayMs, Math.round(rule.baseDelayMs * rule.factor ** n));
      nextAllowedAtMs = now + delay;
    }

    let lockedUntilMs = cooled?.lockedUntilMs ?? 0;
    if (failures >= rule.lockoutAfterFailures) {
      lockedUntilMs = Math.max(lockedUntilMs, now + rule.lockoutMs);
    }

    const expiresAtMs = Math.max(now + rule.failureWindowMs, lockedUntilMs, nextAllowedAtMs);
    this.state.set(key, { failures, lastFailureMs, lockedUntilMs, nextAllowedAtMs, expiresAtMs });
    return this.check(key);
  }

  recordSuccess(key: string): void {
    if (!key) return;
    this.state.delete(key);
  }

  /**
   * Remove expired states to reduce unbounded memory growth under high key cardinality.
   * Returns the number of removed states.
   *
   * Note: this class remains a dev/single-instance utility; for production use a shared store.
   */
  pruneExpired(nowMs: number = this.nowMs()): number {
    let removed = 0;
    for (const [k, s] of this.state) {
      if (nowMs >= s.expiresAtMs) {
        this.state.delete(k);
        removed++;
      }
    }
    return removed;
  }
}

function validateProgressiveRule(rule: ProgressiveDelayRule): void {
  if (!Number.isFinite(rule.failureWindowMs) || rule.failureWindowMs <= 0)
    throw new AuthError('invalid_input', 'progressive delay rule.failureWindowMs must be > 0');
  if (!Number.isFinite(rule.startAfterFailures) || rule.startAfterFailures < 1)
    throw new AuthError('invalid_input', 'progressive delay rule.startAfterFailures must be >= 1');
  if (!Number.isFinite(rule.baseDelayMs) || rule.baseDelayMs < 0)
    throw new AuthError('invalid_input', 'progressive delay rule.baseDelayMs must be >= 0');
  if (!Number.isFinite(rule.factor) || rule.factor < 1)
    throw new AuthError('invalid_input', 'progressive delay rule.factor must be >= 1');
  if (!Number.isFinite(rule.maxDelayMs) || rule.maxDelayMs < 0)
    throw new AuthError('invalid_input', 'progressive delay rule.maxDelayMs must be >= 0');
  if (!Number.isFinite(rule.lockoutAfterFailures) || rule.lockoutAfterFailures < 1)
    throw new AuthError(
      'invalid_input',
      'progressive delay rule.lockoutAfterFailures must be >= 1'
    );
  if (!Number.isFinite(rule.lockoutMs) || rule.lockoutMs < 0)
    throw new AuthError('invalid_input', 'progressive delay rule.lockoutMs must be >= 0');
}
