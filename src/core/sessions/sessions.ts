import { AuthError } from '../auth-error.js';
import type { AuthPolicy } from '../auth-policy.js';
import type {
  CreateSessionTokenResult,
  SessionToken,
  SessionTokenHash,
  UserId
} from '../auth-types.js';
import type { AuthStorage, SessionRecord } from '../storage/auth-storage.js';
import type {
  RevokeSessionInput,
  RevokeSessionResult,
  ValidateSessionInput,
  ValidateSessionResult
} from './session-types.js';

export async function validateSession(ctx: {
  input: ValidateSessionInput;
  storage: AuthStorage;
  policy: AuthPolicy;
  now: () => Date;
  hashSessionToken: (t: SessionToken) => SessionTokenHash;
  createSessionToken: () => CreateSessionTokenResult;
}): Promise<ValidateSessionResult> {
  const token = ctx.input.sessionToken as unknown as string;
  if (typeof token !== 'string' || token.length < 16) {
    return { ok: false, reason: 'missing' };
  }

  const now = ctx.now();
  const tokenHash = ctx.hashSessionToken(ctx.input.sessionToken);
  const session = await ctx.storage.sessions.getSessionByTokenHash(tokenHash);
  if (!session) return { ok: false, reason: 'missing' };
  if (session.revokedAt) return { ok: false, reason: 'revoked' };
  if (session.expiresAt.getTime() <= now.getTime()) return { ok: false, reason: 'expired' };

  if (ctx.policy.session.idleTtlMs !== undefined) {
    const last = (session.lastSeenAt ?? session.createdAt).getTime();
    if (last + ctx.policy.session.idleTtlMs <= now.getTime())
      return { ok: false, reason: 'expired' };
  }

  // Rotation decision
  const rotateEveryMs = ctx.policy.session.rotateEveryMs;
  const lastSeen = session.lastSeenAt ?? session.createdAt;
  const shouldRotate =
    rotateEveryMs !== undefined &&
    rotateEveryMs > 0 &&
    lastSeen.getTime() + rotateEveryMs <= now.getTime();

  if (shouldRotate) {
    const rotated = ctx.createSessionToken();
    const expiresAt = new Date(now.getTime() + ctx.policy.session.absoluteTtlMs);
    const newRecord: SessionRecord = {
      tokenHash: rotated.sessionTokenHash,
      userId: session.userId,
      createdAt: now,
      lastSeenAt: now,
      expiresAt,
      rotatedFromHash: tokenHash
    };

    await ctx.storage.sessions.rotateSession(tokenHash, newRecord, now);
    return { ok: true, userId: session.userId, rotatedSession: rotated };
  }

  // Touch for sliding sessions (reduce write amplification)
  const touchEveryMs = ctx.policy.session.touchEveryMs;
  const shouldTouch =
    touchEveryMs === undefined || touchEveryMs <= 0
      ? true
      : (session.lastSeenAt ?? session.createdAt).getTime() + touchEveryMs <= now.getTime();
  if (shouldTouch) {
    await ctx.storage.sessions.touchSession(tokenHash, now);
  }
  return { ok: true, userId: session.userId };
}

export async function revokeSession(ctx: {
  input: RevokeSessionInput;
  storage: AuthStorage;
  now: () => Date;
  hashSessionToken: (t: SessionToken) => SessionTokenHash;
}): Promise<RevokeSessionResult> {
  const token = ctx.input.sessionToken as unknown as string;
  if (typeof token !== 'string' || token.length < 16) {
    // Logout should be idempotent.
    return { ok: true };
  }
  const now = ctx.now();
  const tokenHash = ctx.hashSessionToken(ctx.input.sessionToken);
  await ctx.storage.sessions.revokeSession(tokenHash, now);
  return { ok: true };
}

export async function revokeAllUserSessions(ctx: {
  userId: UserId;
  storage: AuthStorage;
  now: () => Date;
}): Promise<void> {
  const now = ctx.now();
  await ctx.storage.sessions.revokeAllUserSessions(ctx.userId, now);
}

export function assertNever(_: never): never {
  throw new AuthError('internal_error', 'unreachable');
}
