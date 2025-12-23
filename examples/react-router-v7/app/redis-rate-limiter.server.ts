import { createClient } from 'redis';
import type { RateLimitRule, RateLimitResult } from '@jtwebb/auth/core';

export type RedisClient = ReturnType<typeof createClient>;

/**
 * Redis-backed fixed-window rate limiter compatible with:
 * `rateLimit.limiter?: { consume(key, rule) }` in `createReactRouterAuthAdapter`.
 *
 * - Uses INCR + PEXPIRE (set only on first increment in the window).
 * - Returns retryAfterMs using PTTL when blocked.
 *
 * Notes:
 * - Key cardinality matters: keep your keys bounded (e.g. hash identifiers).
 * - In production, consider adding a prefix per-environment/app.
 */
export function createRedisRateLimiter(options: { redis: RedisClient; keyPrefix?: string }): {
  consume: (key: string, rule: RateLimitRule) => Promise<RateLimitResult>;
} {
  const prefix = options.keyPrefix ?? 'auth:rl:';

  // Atomic: increment, set expiry on first hit, return {count, ttlMs}.
  const lua = `
local k = KEYS[1]
local windowMs = tonumber(ARGV[1])
local count = redis.call("INCR", k)
if count == 1 then
  redis.call("PEXPIRE", k, windowMs)
end
local ttl = redis.call("PTTL", k)
return {count, ttl}
`.trim();

  return {
    async consume(key: string, rule: RateLimitRule): Promise<RateLimitResult> {
      if (!key) return { ok: true };
      const redisKey = `${prefix}${key}`;
      const [count, ttl] = (await options.redis.eval(lua, {
        keys: [redisKey],
        arguments: [String(rule.windowMs)]
      })) as [number, number];

      if (count <= rule.max) return { ok: true };
      return { ok: false, retryAfterMs: Math.max(0, ttl) };
    }
  };
}
