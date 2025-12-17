import { AuthError } from '../auth-error.js';
import type { AuthPolicy } from '../auth-policy.js';
import type {
  PasswordLoginInput,
  PasswordLoginResult,
  PasswordRegisterInput,
  PasswordRegisterResult
} from '../auth-types.js';
import type { AuthStorage, SessionRecord } from '../storage/auth-storage.js';
import type { AuthAttemptEvent } from '../create-auth-core.js';
import { defaultArgon2Params, hashPassword, verifyPassword } from './password-hash.js';
import type { Argon2Params } from './password-hash.js';
import { createTotpPending } from '../totp/totp.js';

export type PasswordAuthContext = {
  input: PasswordLoginInput;
  storage: AuthStorage;
  policy: AuthPolicy;
  now: () => Date;
  createSessionToken: () => { sessionToken: any; sessionTokenHash: any };
  randomBytes: (size: number) => Uint8Array;
  passwordPepper?: string | Uint8Array;
  passwordHashParams?: Partial<Argon2Params>;
  onAuthAttempt?: (event: AuthAttemptEvent) => void | Promise<void>;
};

export type PasswordRegisterContext = {
  input: PasswordRegisterInput;
  storage: AuthStorage;
  policy: AuthPolicy;
  now: () => Date;
  createSessionToken: () => { sessionToken: any; sessionTokenHash: any };
  passwordPepper?: string | Uint8Array;
  passwordHashParams?: Partial<Argon2Params>;
  onAuthAttempt?: (event: AuthAttemptEvent) => void | Promise<void>;
};

export async function registerWithPassword(
  ctx: PasswordRegisterContext
): Promise<PasswordRegisterResult> {
  const { input, storage, policy } = ctx;
  const identifier = normalizeIdentifier(input.identifier);
  validatePasswordAgainstPolicy(input.password, policy);

  const now = ctx.now();
  const expiresAt = new Date(now.getTime() + policy.session.absoluteTtlMs);

  let userId: string;
  try {
    userId = (await storage.users.createUser(identifier)) as unknown as string;
  } catch (cause) {
    await safeAttemptHook(ctx.onAuthAttempt, {
      type: 'password_register',
      identifier,
      ok: false,
      reason: 'conflict'
    });
    throw new AuthError('conflict', 'Identifier already in use', {
      cause,
      publicMessage: 'Unable to create account',
      status: 409
    });
  }

  const passwordHash = await hashPassword(input.password, {
    pepper: ctx.passwordPepper,
    params: { ...defaultArgon2Params, ...(ctx.passwordHashParams ?? {}) }
  });

  await storage.passwordCredentials.upsertForUser({
    userId: userId as any,
    passwordHash,
    createdAt: now
  });

  const session = ctx.createSessionToken();
  const sessionRecord: SessionRecord = {
    tokenHash: session.sessionTokenHash,
    userId: userId as any,
    createdAt: now,
    lastSeenAt: now,
    expiresAt
  };
  await storage.sessions.createSession(sessionRecord);

  await safeAttemptHook(ctx.onAuthAttempt, {
    type: 'password_register',
    identifier,
    userId,
    ok: true
  });

  return { userId: userId as any, session };
}

export async function loginWithPassword(ctx: PasswordAuthContext): Promise<PasswordLoginResult> {
  const { input, storage, policy } = ctx;
  const identifier = normalizeIdentifier(input.identifier);
  validatePasswordAgainstPolicy(input.password, policy);

  const now = ctx.now();

  const userId = await storage.users.getUserIdByIdentifier(identifier);
  if (!userId) {
    // Spend comparable work to reduce identifier enumeration.
    await dummyVerify(input.password, ctx.passwordPepper, ctx.passwordHashParams);
    await safeAttemptHook(ctx.onAuthAttempt, {
      type: 'password_login',
      identifier,
      ok: false,
      reason: 'not_found'
    });
    throw invalidCredentials();
  }

  const cred = await storage.passwordCredentials.getForUser(userId);
  if (!cred) {
    await dummyVerify(input.password, ctx.passwordPepper, ctx.passwordHashParams);
    await safeAttemptHook(ctx.onAuthAttempt, {
      type: 'password_login',
      identifier,
      userId: userId as unknown as string,
      ok: false,
      reason: 'no_password_credential'
    });
    throw invalidCredentials();
  }

  const desiredParams = { ...defaultArgon2Params, ...(ctx.passwordHashParams ?? {}) };
  const result = await verifyPassword(input.password, cred.passwordHash, {
    pepper: ctx.passwordPepper,
    desiredParams
  });

  if (!result.ok) {
    await safeAttemptHook(ctx.onAuthAttempt, {
      type: 'password_login',
      identifier,
      userId: userId as unknown as string,
      ok: false,
      reason: 'invalid_password'
    });
    throw invalidCredentials();
  }

  if (result.needsRehash) {
    const upgraded = await hashPassword(input.password, {
      pepper: ctx.passwordPepper,
      params: desiredParams
    });
    await storage.passwordCredentials.upsertForUser({
      userId,
      passwordHash: upgraded,
      createdAt: cred.createdAt,
      updatedAt: now
    });
  }

  // If TOTP is enabled, require step-up instead of issuing a session immediately.
  const totpEnabled = await storage.totp.getEnabled(userId);
  if (totpEnabled) {
    const pendingToken = await createTotpPending({
      userId,
      storage,
      now: () => now,
      randomBytes: ctx.randomBytes,
      ttlMs: policy.challenge.ttlMs
    });
    await safeAttemptHook(ctx.onAuthAttempt, {
      type: 'password_login',
      identifier,
      userId: userId as unknown as string,
      ok: true
    });
    return { twoFactorRequired: true, userId, pendingToken };
  }

  const session = ctx.createSessionToken();
  const expiresAt = new Date(now.getTime() + policy.session.absoluteTtlMs);
  await storage.sessions.createSession({
    tokenHash: session.sessionTokenHash,
    userId,
    createdAt: now,
    lastSeenAt: now,
    expiresAt
  });

  await safeAttemptHook(ctx.onAuthAttempt, {
    type: 'password_login',
    identifier,
    userId: userId as unknown as string,
    ok: true
  });

  return { userId, session };
}

function normalizeIdentifier(identifier: string): string {
  if (typeof identifier !== 'string')
    throw new AuthError('invalid_input', 'identifier must be a string');
  const trimmed = identifier.trim();
  if (!trimmed) throw new AuthError('invalid_input', 'identifier is required');
  if (trimmed.length > 320) throw new AuthError('invalid_input', 'identifier is too long');
  return trimmed;
}

function validatePasswordAgainstPolicy(password: string, policy: AuthPolicy): void {
  if (typeof password !== 'string')
    throw new AuthError('invalid_input', 'password must be a string');
  if (password.length < policy.password.minLength)
    throw new AuthError('invalid_input', 'password is too short');
  if (password.length > policy.password.maxLength)
    throw new AuthError('invalid_input', 'password is too long');
}

function invalidCredentials(): AuthError {
  // Keep message generic to avoid enumeration.
  return new AuthError('password_invalid', 'Invalid credentials', {
    publicMessage: 'Invalid credentials',
    status: 401
  });
}

async function safeAttemptHook(
  hook: ((event: AuthAttemptEvent) => void | Promise<void>) | undefined,
  event: AuthAttemptEvent
): Promise<void> {
  try {
    await hook?.(event);
  } catch {
    // Never let audit/rate-limit hooks break authentication.
  }
}

async function dummyVerify(
  password: string,
  pepper: string | Uint8Array | undefined,
  passwordHashParams: Partial<Argon2Params> | undefined
): Promise<void> {
  // Spend comparable CPU to reduce identifier enumeration.
  // A fixed hash is fine here because we don't need to store anything; we just want similar work.
  const desiredParams = { ...defaultArgon2Params, ...(passwordHashParams ?? {}) };
  const dummyHash = await hashPassword('dummy-password-do-not-use', {
    pepper,
    params: desiredParams
  });
  await verifyPassword(password, dummyHash, { pepper, desiredParams });
}
