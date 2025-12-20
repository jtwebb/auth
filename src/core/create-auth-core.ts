import { createHash, createHmac, randomBytes as nodeRandomBytes } from 'node:crypto';
import { AuthError, isAuthError } from './auth-error.js';
import type { AuthPolicy } from './auth-policy.js';
import { getAuthPolicyForSecurityProfile, type SecurityProfile } from './auth-policy.js';
import type {
  CreateSessionTokenResult,
  PasswordLoginInput,
  PasswordLoginResult,
  PasswordRegisterInput,
  PasswordRegisterResult,
  PasswordResetToken,
  PasswordResetTokenHash,
  SessionToken,
  SessionTokenHash,
  UserId
} from './auth-types.js';
import { loginWithPassword, registerWithPassword } from './password/password-auth.js';
import type { Argon2Params } from './password/password-hash.js';
import { defaultArgon2Params, hashPassword } from './password/password-hash.js';
import type { AuthStorage, SessionRecord } from './storage/auth-storage.js';
import type {
  PasskeyLoginFinishInput,
  PasskeyLoginFinishResult,
  PasskeyLoginStartInput,
  PasskeyLoginStartResult,
  PasskeyRegistrationFinishInput,
  PasskeyRegistrationFinishResult,
  PasskeyRegistrationStartInput,
  PasskeyRegistrationStartResult
} from './passkey/passkey-types.js';
import {
  finishPasskeyLogin,
  finishPasskeyRegistration,
  startPasskeyLogin,
  startPasskeyRegistration
} from './passkey/passkey-auth.js';
import type {
  RedeemBackupCodeInput,
  RedeemBackupCodeResult,
  RotateBackupCodesInput,
  RotateBackupCodesResult
} from './backup-codes/backup-code-types.js';
import { redeemBackupCode, rotateBackupCodes } from './backup-codes/backup-codes.js';
import type {
  RevokeSessionInput,
  RevokeSessionResult,
  ValidateSessionInput,
  ValidateSessionResult
} from './sessions/session-types.js';
import { revokeAllUserSessions, revokeSession, validateSession } from './sessions/sessions.js';
import type {
  FinishTotpEnrollmentInput,
  FinishTotpEnrollmentResult,
  StartTotpEnrollmentInput,
  StartTotpEnrollmentResult,
  VerifyTotpInput,
  VerifyTotpResult
} from './totp/totp-types.js';
import { finishTotpEnrollment, startTotpEnrollment, verifyTotp } from './totp/totp.js';
import type { TotpEncryptionKey } from './totp/totp-crypto.js';

export type RandomBytesFn = (size: number) => Uint8Array;
export type Clock = { now: () => Date };

export type AuthAttemptEvent =
  | {
      type: 'password_login';
      /**
       * Privacy-safe identifier. Prefer HMAC-SHA256(identifier, secret).
       * Never includes the raw identifier (email/username).
       */
      identifierHash: string;
      userId?: string;
      ok: boolean;
      reason?: 'not_found' | 'no_password_credential' | 'invalid_password';
    }
  | {
      type: 'password_register';
      /**
       * Privacy-safe identifier. Prefer HMAC-SHA256(identifier, secret).
       * Never includes the raw identifier (email/username).
       */
      identifierHash: string;
      userId?: string;
      ok: boolean;
      reason?: 'conflict';
    }
  | {
      type: 'logout';
      userId?: string;
      ok: boolean;
    }
  | {
      type: 'sessions_revoke_all';
      userId: string;
      ok: boolean;
    }
  | {
      type: 'sessions_revoke_other';
      userId: string;
      ok: boolean;
    }
  | {
      type: 'passkey_register_start';
      userId: string;
      ok: boolean;
    }
  | {
      type: 'passkey_register_finish';
      userId: string;
      credentialId?: string;
      ok: boolean;
      reason?: 'invalid' | 'expired';
    }
  | {
      type: 'totp_verify';
      userId?: string;
      ok: boolean;
      reason?: 'invalid' | 'expired' | 'not_enabled';
    }
  | {
      type: 'totp_enroll_start';
      userId: string;
      ok: boolean;
    }
  | {
      type: 'totp_enroll_finish';
      userId: string;
      ok: boolean;
      reason?: 'invalid' | 'already_enabled' | 'no_pending';
    }
  | {
      type: 'totp_disable';
      userId: string;
      ok: boolean;
    }
  | {
      type: 'backup_codes_rotate';
      userId: string;
      ok: boolean;
    }
  | {
      type: 'backup_code_redeem';
      userId: string;
      ok: boolean;
      reason?: 'invalid';
    }
  | {
      type: 'passkey_login_finish';
      userId?: string;
      ok: boolean;
      reason?: 'invalid' | 'expired';
    };

export type CreateAuthCoreOptions = {
  storage: AuthStorage;
  /**
   * Inject for testability; defaults to Node's crypto.randomBytes.
   */
  randomBytes?: RandomBytesFn;
  /**
   * Inject for testability; defaults to new Date().
   */
  clock?: Clock;
  /**
   * Optional app-level pepper (secret) mixed into password hashing.
   * Store it in a secret manager; changing it invalidates all stored passwords.
   */
  passwordPepper?: Uint8Array | string;
  /**
   * Override default Argon2id parameters (advanced).
   */
  passwordHashParams?: Partial<Argon2Params>;
  /**
   * Hook for logging/rate limiting/auditing (do not log passwords).
   */
  onAuthAttempt?: (event: AuthAttemptEvent) => void | Promise<void>;
  /**
   * Security presets that configure policy defaults.
   * Defaults to "balanced".
   */
  securityProfile?: SecurityProfile;
  /**
   * If provided, we hash session tokens using HMAC-SHA256(token, secret).
   * Otherwise, SHA-256(token).
   */
  sessionTokenHashSecret?: Uint8Array | string;
  /**
   * Optional secret used to hash identifiers for audit/rate-limit events.
   * If omitted, we fall back to sessionTokenHashSecret when present, otherwise SHA-256.
   */
  identifierHashSecret?: Uint8Array | string;
  /**
   * Optional secret used to hash session binding context values (clientId/userAgent).
   * If omitted, we fall back to sessionTokenHashSecret when present, otherwise SHA-256.
   */
  sessionContextHashSecret?: Uint8Array | string;
  /**
   * Optional secret used to HMAC password reset tokens before storing.
   * Strongly recommended to mitigate offline guessing if DB is leaked.
   */
  passwordResetTokenHashSecret?: Uint8Array | string;
  /**
   * Optional secret used to HMAC backup codes before storing.
   * Strongly recommended to mitigate offline guessing if DB is leaked.
   */
  backupCodeHashSecret?: Uint8Array | string;
  /**
   * Required to enable TOTP features. Store in a secrets manager.
   */
  totpEncryptionKey?: TotpEncryptionKey;
  policy?: Partial<AuthPolicy>;
};

export type AuthCore = {
  readonly policy: AuthPolicy;
  createSessionToken(): CreateSessionTokenResult;
  hashSessionToken(sessionToken: SessionToken): SessionTokenHash;

  // Commands (implemented in later milestones)
  registerPassword(input: PasswordRegisterInput): Promise<PasswordRegisterResult>;
  loginPassword(input: PasswordLoginInput): Promise<PasswordLoginResult>;
  startPasskeyRegistration(
    input: PasskeyRegistrationStartInput
  ): Promise<PasskeyRegistrationStartResult>;
  finishPasskeyRegistration(
    input: PasskeyRegistrationFinishInput
  ): Promise<PasskeyRegistrationFinishResult>;
  startPasskeyLogin(input: PasskeyLoginStartInput): Promise<PasskeyLoginStartResult>;
  finishPasskeyLogin(input: PasskeyLoginFinishInput): Promise<PasskeyLoginFinishResult>;
  rotateBackupCodes(input: RotateBackupCodesInput): Promise<RotateBackupCodesResult>;
  redeemBackupCode(input: RedeemBackupCodeInput): Promise<RedeemBackupCodeResult>;
  validateSession(input: ValidateSessionInput): Promise<ValidateSessionResult>;
  revokeSession(input: RevokeSessionInput): Promise<RevokeSessionResult>;
  revokeAllUserSessions(userId: UserId): Promise<void>;
  /**
   * Session management helpers (optional storage support required).
   */
  listSessions(userId: UserId): Promise<SessionRecord[]>;
  revokeSessionById(input: { sessionId: SessionTokenHash }): Promise<void>;
  revokeOtherSessions(input: { userId: UserId; currentSessionToken: SessionToken }): Promise<void>;

  /**
   * Password reset / account recovery primitives.
   */
  createPasswordResetToken(input: {
    userId: UserId;
  }): Promise<{ token: PasswordResetToken; expiresAt: Date }>;
  startPasswordReset(input: {
    identifier: string;
  }): Promise<{ ok: true; created: boolean; token?: PasswordResetToken; expiresAt?: Date }>;
  resetPasswordWithToken(input: {
    token: PasswordResetToken;
    newPassword: string;
    revokeAllUserSessions?: boolean;
  }): Promise<{ ok: true; userId: UserId }>;
  startTotpEnrollment(input: StartTotpEnrollmentInput): Promise<StartTotpEnrollmentResult>;
  finishTotpEnrollment(input: FinishTotpEnrollmentInput): Promise<FinishTotpEnrollmentResult>;
  disableTotp(input: { userId: UserId }): Promise<{ ok: true }>;
  verifyTotp(input: VerifyTotpInput): Promise<VerifyTotpResult>;
};

export function createAuthCore(options: CreateAuthCoreOptions): AuthCore {
  if (!options || typeof options !== 'object') {
    throw new AuthError('invalid_input', 'createAuthCore: options must be an object');
  }
  if (!options.storage) {
    throw new AuthError('invalid_input', 'createAuthCore: storage is required');
  }

  const basePolicy = getAuthPolicyForSecurityProfile(options.securityProfile ?? 'balanced');
  const policy: AuthPolicy = mergePolicy(basePolicy, options.policy);
  validatePolicy(policy);

  const randomBytes: RandomBytesFn = options.randomBytes ?? nodeRandomBytes;
  const clock: Clock = options.clock ?? { now: () => new Date() };

  const hashSessionToken = (sessionToken: SessionToken): SessionTokenHash => {
    const token = sessionToken as unknown as string;
    if (typeof token !== 'string' || token.length < 16) {
      throw new AuthError('invalid_input', 'sessionToken must be a non-empty token string');
    }

    // Hex for DB friendliness (fixed length, easy indexing).
    const digestHex =
      options.sessionTokenHashSecret !== undefined
        ? createHmac('sha256', options.sessionTokenHashSecret).update(token).digest('hex')
        : createHash('sha256').update(token).digest('hex');

    return digestHex as SessionTokenHash;
  };

  const hashSessionContextValue = (value: string): string => {
    const v = String(value ?? '');
    const secret = options.sessionContextHashSecret ?? options.sessionTokenHashSecret;
    const digestHex =
      secret !== undefined
        ? createHmac('sha256', secret).update(v).digest('hex')
        : createHash('sha256').update(v).digest('hex');
    return digestHex;
  };

  const hashPasswordResetToken = (token: PasswordResetToken): PasswordResetTokenHash => {
    const t = token as unknown as string;
    if (typeof t !== 'string' || t.length < 16) {
      throw new AuthError('invalid_input', 'password reset token must be a non-empty token string');
    }
    const secret = options.passwordResetTokenHashSecret ?? options.sessionTokenHashSecret;
    const digestHex =
      secret !== undefined
        ? createHmac('sha256', secret).update(t).digest('hex')
        : createHash('sha256').update(t).digest('hex');
    return digestHex as PasswordResetTokenHash;
  };

  const createSessionToken = (): CreateSessionTokenResult => {
    const now = clock.now();
    if (!(now instanceof Date) || Number.isNaN(now.getTime())) {
      throw new AuthError('invalid_input', 'clock.now() must return a valid Date');
    }
    // 32 bytes → 256-bit token.
    const bytes = randomBytes(32);
    if (!(bytes instanceof Uint8Array) || bytes.length !== 32) {
      throw new AuthError('internal_error', 'randomBytes must return 32 bytes');
    }
    const sessionToken = base64UrlEncode(bytes) as SessionToken;
    const sessionTokenHash = hashSessionToken(sessionToken);
    return { sessionToken, sessionTokenHash };
  };

  const createPasswordResetToken = async (userId: UserId) => {
    const storage = options.storage.passwordResetTokens;
    if (!storage)
      throw new AuthError('not_implemented', 'passwordResetTokens storage not implemented');
    const now = clock.now();
    const bytes = randomBytes(32);
    if (!(bytes instanceof Uint8Array) || bytes.length !== 32) {
      throw new AuthError('internal_error', 'randomBytes must return 32 bytes');
    }
    const token = base64UrlEncode(bytes) as PasswordResetToken;
    const tokenHash = hashPasswordResetToken(token);
    const expiresAt = new Date(now.getTime() + policy.passwordReset.tokenTtlMs);
    await storage.createToken({ tokenHash, userId, createdAt: now, expiresAt });
    return { token, expiresAt };
  };

  const startPasswordReset = async (identifier: string) => {
    const userId = await options.storage.users.getUserIdByIdentifier(identifier);
    // Do comparable work regardless of whether user exists (avoid easy timing enumeration).
    // We always generate a token + hash; we only persist it if the user exists.
    const bytes = randomBytes(32);
    const token = base64UrlEncode(bytes) as PasswordResetToken;
    void hashPasswordResetToken(token);
    if (!userId) return { ok: true as const, created: false as const };
    const created = await createPasswordResetToken(userId);
    return {
      ok: true as const,
      created: true as const,
      token: created.token,
      expiresAt: created.expiresAt
    };
  };

  const resetPasswordWithToken = async (input: {
    token: PasswordResetToken;
    newPassword: string;
    revokeAllUserSessions?: boolean;
  }) => {
    const storage = options.storage.passwordResetTokens;
    if (!storage)
      throw new AuthError('not_implemented', 'passwordResetTokens storage not implemented');
    if (typeof input.newPassword !== 'string')
      throw new AuthError('invalid_input', 'newPassword must be a string');
    if (input.newPassword.length < policy.password.minLength)
      throw new AuthError('invalid_input', 'password is too short');
    if (input.newPassword.length > policy.password.maxLength)
      throw new AuthError('invalid_input', 'password is too long');

    const now = clock.now();
    const tokenHash = hashPasswordResetToken(input.token);
    const consumed = await storage.consumeToken(tokenHash, now);
    if (!consumed) {
      throw new AuthError('password_reset_invalid', 'Invalid or expired password reset token', {
        publicMessage: 'Invalid or expired password reset token',
        status: 401
      });
    }

    const desiredParams = { ...defaultArgon2Params, ...(options.passwordHashParams ?? {}) };
    const passwordHash = await hashPassword(input.newPassword, {
      pepper: options.passwordPepper,
      params: desiredParams
    });

    const existing = await options.storage.passwordCredentials.getForUser(consumed.userId);
    await options.storage.passwordCredentials.upsertForUser({
      userId: consumed.userId,
      passwordHash,
      createdAt: existing?.createdAt ?? now,
      updatedAt: now
    });

    const revoke = input.revokeAllUserSessions ?? true;
    if (revoke) {
      await options.storage.sessions.revokeAllUserSessions(consumed.userId, now);
    }
    return { ok: true as const, userId: consumed.userId };
  };

  return {
    policy,
    createSessionToken,
    hashSessionToken,

    registerPassword: async input =>
      registerWithPassword({
        input,
        storage: options.storage,
        policy,
        now: () => clock.now(),
        createSessionToken,
        hashSessionContextValue,
        passwordPepper: options.passwordPepper,
        passwordHashParams: options.passwordHashParams,
        onAuthAttempt: options.onAuthAttempt,
        identifierHashSecret: options.identifierHashSecret ?? options.sessionTokenHashSecret
      }),
    loginPassword: async input =>
      loginWithPassword({
        input,
        storage: options.storage,
        policy,
        now: () => clock.now(),
        createSessionToken,
        randomBytes,
        hashSessionContextValue,
        passwordPepper: options.passwordPepper,
        passwordHashParams: options.passwordHashParams,
        onAuthAttempt: options.onAuthAttempt,
        identifierHashSecret: options.identifierHashSecret ?? options.sessionTokenHashSecret
      }),
    startPasskeyRegistration: async input =>
      (async () => {
        try {
          const out = await startPasskeyRegistration({
            input,
            storage: options.storage,
            policy,
            now: () => clock.now(),
            randomBytes
          });
          await safeAttemptHook(options.onAuthAttempt, {
            type: 'passkey_register_start',
            userId: input.userId as unknown as string,
            ok: true
          });
          return out;
        } catch (err) {
          await safeAttemptHook(options.onAuthAttempt, {
            type: 'passkey_register_start',
            userId: input.userId as unknown as string,
            ok: false
          });
          throw err;
        }
      })(),
    finishPasskeyRegistration: async input =>
      (async () => {
        try {
          const out = await finishPasskeyRegistration({
            input,
            storage: options.storage,
            policy,
            now: () => clock.now()
          });
          await safeAttemptHook(options.onAuthAttempt, {
            type: 'passkey_register_finish',
            userId: input.userId as unknown as string,
            credentialId: out.credentialId as unknown as string,
            ok: true
          });
          return out;
        } catch (err) {
          await safeAttemptHook(options.onAuthAttempt, {
            type: 'passkey_register_finish',
            userId: input.userId as unknown as string,
            ok: false,
            reason: isAuthError(err) && err.code === 'challenge_expired' ? 'expired' : 'invalid'
          });
          throw err;
        }
      })(),
    startPasskeyLogin: async input =>
      startPasskeyLogin({
        input,
        storage: options.storage,
        policy,
        now: () => clock.now(),
        randomBytes
      }),
    finishPasskeyLogin: async input =>
      (async () => {
        try {
          const out = await finishPasskeyLogin({
            input,
            storage: options.storage,
            policy,
            now: () => clock.now(),
            createSessionToken,
            randomBytes,
            hashSessionContextValue
          });
          await safeAttemptHook(options.onAuthAttempt, {
            type: 'passkey_login_finish',
            userId: out.userId as unknown as string,
            ok: true
          });
          return out;
        } catch (err) {
          await safeAttemptHook(options.onAuthAttempt, {
            type: 'passkey_login_finish',
            ok: false,
            reason: isAuthError(err) && err.code === 'challenge_expired' ? 'expired' : 'invalid'
          });
          throw err;
        }
      })(),
    rotateBackupCodes: async input =>
      (async () => {
        try {
          const out = await rotateBackupCodes({
            input,
            storage: options.storage,
            policy,
            now: () => clock.now(),
            randomBytes,
            backupCodeHashSecret: options.backupCodeHashSecret
          });
          await safeAttemptHook(options.onAuthAttempt, {
            type: 'backup_codes_rotate',
            userId: input.userId as unknown as string,
            ok: true
          });
          return out;
        } catch (err) {
          await safeAttemptHook(options.onAuthAttempt, {
            type: 'backup_codes_rotate',
            userId: input.userId as unknown as string,
            ok: false
          });
          throw err;
        }
      })(),
    redeemBackupCode: async input =>
      (async () => {
        try {
          const out = await redeemBackupCode({
            input,
            storage: options.storage,
            now: () => clock.now(),
            backupCodeHashSecret: options.backupCodeHashSecret
          });
          await safeAttemptHook(options.onAuthAttempt, {
            type: 'backup_code_redeem',
            userId: input.userId as unknown as string,
            ok: true
          });
          return out;
        } catch (err) {
          await safeAttemptHook(options.onAuthAttempt, {
            type: 'backup_code_redeem',
            userId: input.userId as unknown as string,
            ok: false,
            reason: 'invalid'
          });
          throw err;
        }
      })(),
    validateSession: async input =>
      validateSession({
        input,
        storage: options.storage,
        policy,
        now: () => clock.now(),
        hashSessionToken,
        hashSessionContextValue,
        createSessionToken
      }),
    revokeSession: async input =>
      (async () => {
        try {
          const token = input.sessionToken as unknown as string;
          let userId: string | undefined = undefined;
          if (typeof token === 'string' && token.length >= 16) {
            const h = hashSessionToken(input.sessionToken);
            const s = await options.storage.sessions.getSessionByTokenHash(h);
            userId = s?.userId as unknown as string | undefined;
          }
          const out = await revokeSession({
            input,
            storage: options.storage,
            now: () => clock.now(),
            hashSessionToken
          });
          await safeAttemptHook(options.onAuthAttempt, { type: 'logout', userId, ok: true });
          return out;
        } catch (err) {
          await safeAttemptHook(options.onAuthAttempt, { type: 'logout', ok: false });
          throw err;
        }
      })(),
    revokeAllUserSessions: async userId =>
      (async () => {
        try {
          await revokeAllUserSessions({
            userId,
            storage: options.storage,
            now: () => clock.now()
          });
          await safeAttemptHook(options.onAuthAttempt, {
            type: 'sessions_revoke_all',
            userId: userId as unknown as string,
            ok: true
          });
        } catch (err) {
          await safeAttemptHook(options.onAuthAttempt, {
            type: 'sessions_revoke_all',
            userId: userId as unknown as string,
            ok: false
          });
          throw err;
        }
      })(),
    listSessions: async userId => {
      const fn = options.storage.sessions.listSessionsForUser;
      if (!fn)
        throw new AuthError('not_implemented', 'sessions.listSessionsForUser not implemented');
      return await fn(userId);
    },
    revokeSessionById: async input => {
      await options.storage.sessions.revokeSession(input.sessionId, clock.now());
    },
    revokeOtherSessions: async input =>
      (async () => {
        try {
          const fn = options.storage.sessions.revokeAllUserSessionsExceptTokenHash;
          if (!fn)
            throw new AuthError(
              'not_implemented',
              'sessions.revokeAllUserSessionsExceptTokenHash not implemented'
            );
          const currentHash = hashSessionToken(input.currentSessionToken);
          await fn(input.userId, currentHash, clock.now());
          await safeAttemptHook(options.onAuthAttempt, {
            type: 'sessions_revoke_other',
            userId: input.userId as unknown as string,
            ok: true
          });
        } catch (err) {
          await safeAttemptHook(options.onAuthAttempt, {
            type: 'sessions_revoke_other',
            userId: input.userId as unknown as string,
            ok: false
          });
          throw err;
        }
      })(),
    createPasswordResetToken: async input => createPasswordResetToken(input.userId),
    startPasswordReset: async input => startPasswordReset(input.identifier),
    resetPasswordWithToken: async input => resetPasswordWithToken(input),
    startTotpEnrollment: async input =>
      (async () => {
        try {
          if (!options.totpEncryptionKey)
            throw new AuthError('invalid_input', 'totpEncryptionKey is required');
          const out = await startTotpEnrollment({
            input,
            storage: options.storage,
            policy,
            now: () => clock.now(),
            totpEncryptionKey: options.totpEncryptionKey,
            randomBytes
          });
          await safeAttemptHook(options.onAuthAttempt, {
            type: 'totp_enroll_start',
            userId: input.userId as unknown as string,
            ok: true
          });
          return out;
        } catch (err) {
          await safeAttemptHook(options.onAuthAttempt, {
            type: 'totp_enroll_start',
            userId: input.userId as unknown as string,
            ok: false
          });
          throw err;
        }
      })(),
    finishTotpEnrollment: async input =>
      (async () => {
        try {
          if (!options.totpEncryptionKey)
            throw new AuthError('invalid_input', 'totpEncryptionKey is required');
          const out = await finishTotpEnrollment({
            input,
            storage: options.storage,
            policy,
            now: () => clock.now(),
            totpEncryptionKey: options.totpEncryptionKey
          });
          await safeAttemptHook(options.onAuthAttempt, {
            type: 'totp_enroll_finish',
            userId: input.userId as unknown as string,
            ok: true
          });
          return out;
        } catch (err) {
          let reason: 'invalid' | 'already_enabled' | 'no_pending' = 'invalid';
          if (isAuthError(err)) {
            if (err.code === 'conflict') reason = 'already_enabled';
            if (err.code === 'not_found') reason = 'no_pending';
          }
          await safeAttemptHook(options.onAuthAttempt, {
            type: 'totp_enroll_finish',
            userId: input.userId as unknown as string,
            ok: false,
            reason
          });
          throw err;
        }
      })(),
    disableTotp: async input =>
      (async () => {
        const now = clock.now();
        await options.storage.totp.disable(input.userId, now);
        await safeAttemptHook(options.onAuthAttempt, {
          type: 'totp_disable',
          userId: input.userId as unknown as string,
          ok: true
        });
        return { ok: true as const };
      })(),
    verifyTotp: async input => {
      if (!options.totpEncryptionKey)
        throw new AuthError('invalid_input', 'totpEncryptionKey is required');
      try {
        const out = await verifyTotp({
          input,
          storage: options.storage,
          policy,
          now: () => clock.now(),
          totpEncryptionKey: options.totpEncryptionKey,
          createSessionToken,
          hashSessionContextValue
        });
        await safeAttemptHook(options.onAuthAttempt, {
          type: 'totp_verify',
          userId: out.userId as unknown as string,
          ok: true
        });
        return out;
      } catch (err) {
        let reason: 'invalid' | 'expired' | 'not_enabled' = 'invalid';
        if (isAuthError(err)) {
          if (err.code === 'challenge_expired') reason = 'expired';
          if (err.code === 'totp_not_enabled') reason = 'not_enabled';
        }
        await safeAttemptHook(options.onAuthAttempt, { type: 'totp_verify', ok: false, reason });
        throw err;
      }
    }
  };
}

function base64UrlEncode(bytes: Uint8Array): string {
  // Node 20 supports base64url, but do it explicitly to avoid runtime differences.
  return Buffer.from(bytes)
    .toString('base64')
    .replaceAll('+', '-')
    .replaceAll('/', '_')
    .replaceAll('=', '');
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

function mergePolicy(base: AuthPolicy, override?: Partial<AuthPolicy>): AuthPolicy {
  if (!override) return base;
  return {
    ...base,
    ...override,
    password: { ...base.password, ...override.password },
    passkey: { ...base.passkey, ...override.passkey },
    backupCodes: { ...base.backupCodes, ...override.backupCodes },
    session: { ...base.session, ...override.session },
    challenge: { ...base.challenge, ...override.challenge },
    passwordReset: { ...base.passwordReset, ...override.passwordReset }
  };
}

function validatePolicy(policy: AuthPolicy): void {
  if (policy.password.minLength < 8) {
    throw new AuthError('invalid_input', 'policy.password.minLength must be >= 8');
  }
  if (policy.password.maxLength < policy.password.minLength) {
    throw new AuthError('invalid_input', 'policy.password.maxLength must be >= minLength');
  }
  if (!policy.passkey.rpId) {
    throw new AuthError('invalid_input', 'policy.passkey.rpId is required');
  }
  if (!policy.passkey.rpName) {
    throw new AuthError('invalid_input', 'policy.passkey.rpName is required');
  }
  if (!policy.passkey.origins || policy.passkey.origins.length === 0) {
    throw new AuthError('invalid_input', 'policy.passkey.origins must contain at least one origin');
  }
  if (policy.backupCodes.count < 1 || policy.backupCodes.count > 100) {
    throw new AuthError('invalid_input', 'policy.backupCodes.count must be between 1 and 100');
  }
  if (policy.backupCodes.length < 8 || policy.backupCodes.length > 64) {
    throw new AuthError('invalid_input', 'policy.backupCodes.length must be between 8 and 64');
  }
  if (!policy.totp.issuer) {
    throw new AuthError('invalid_input', 'policy.totp.issuer is required');
  }
  if (policy.totp.allowedSkewSteps < 0 || policy.totp.allowedSkewSteps > 10) {
    throw new AuthError('invalid_input', 'policy.totp.allowedSkewSteps must be between 0 and 10');
  }
  if (policy.session.absoluteTtlMs < 1000 * 60) {
    throw new AuthError('invalid_input', 'policy.session.absoluteTtlMs must be at least 1 minute');
  }
  if (policy.session.touchEveryMs !== undefined && policy.session.touchEveryMs < 0) {
    throw new AuthError('invalid_input', 'policy.session.touchEveryMs must be >= 0');
  }
  if (policy.challenge.ttlMs < 1000 * 30) {
    throw new AuthError('invalid_input', 'policy.challenge.ttlMs must be at least 30 seconds');
  }
  if (policy.passwordReset.tokenTtlMs < 1000 * 60) {
    throw new AuthError(
      'invalid_input',
      'policy.passwordReset.tokenTtlMs must be at least 1 minute'
    );
  }
}
