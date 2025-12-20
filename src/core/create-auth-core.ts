import { createHash, createHmac, randomBytes as nodeRandomBytes } from 'node:crypto';
import { AuthError, isAuthError } from './auth-error.js';
import type { AuthPolicy } from './auth-policy.js';
import { defaultAuthPolicy } from './auth-policy.js';
import type {
  CreateSessionTokenResult,
  PasswordLoginInput,
  PasswordLoginResult,
  PasswordRegisterInput,
  PasswordRegisterResult,
  SessionToken,
  SessionTokenHash,
  UserId
} from './auth-types.js';
import { loginWithPassword, registerWithPassword } from './password/password-auth.js';
import type { Argon2Params } from './password/password-hash.js';
import type { AuthStorage } from './storage/auth-storage.js';
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
      identifier: string;
      userId?: string;
      ok: boolean;
      reason?: 'not_found' | 'no_password_credential' | 'invalid_password';
    }
  | {
      type: 'password_register';
      identifier: string;
      userId?: string;
      ok: boolean;
      reason?: 'conflict';
    }
  | {
      type: 'totp_verify';
      userId?: string;
      ok: boolean;
      reason?: 'invalid' | 'expired' | 'not_enabled';
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
   * If provided, we hash session tokens using HMAC-SHA256(token, secret).
   * Otherwise, SHA-256(token).
   */
  sessionTokenHashSecret?: Uint8Array | string;
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
  startTotpEnrollment(input: StartTotpEnrollmentInput): Promise<StartTotpEnrollmentResult>;
  finishTotpEnrollment(input: FinishTotpEnrollmentInput): Promise<FinishTotpEnrollmentResult>;
  verifyTotp(input: VerifyTotpInput): Promise<VerifyTotpResult>;
};

export function createAuthCore(options: CreateAuthCoreOptions): AuthCore {
  if (!options || typeof options !== 'object') {
    throw new AuthError('invalid_input', 'createAuthCore: options must be an object');
  }
  if (!options.storage) {
    throw new AuthError('invalid_input', 'createAuthCore: storage is required');
  }

  const policy: AuthPolicy = mergePolicy(defaultAuthPolicy, options.policy);
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
        passwordPepper: options.passwordPepper,
        passwordHashParams: options.passwordHashParams,
        onAuthAttempt: options.onAuthAttempt
      }),
    loginPassword: async input =>
      loginWithPassword({
        input,
        storage: options.storage,
        policy,
        now: () => clock.now(),
        createSessionToken,
        randomBytes,
        passwordPepper: options.passwordPepper,
        passwordHashParams: options.passwordHashParams,
        onAuthAttempt: options.onAuthAttempt
      }),
    startPasskeyRegistration: async input =>
      startPasskeyRegistration({
        input,
        storage: options.storage,
        policy,
        now: () => clock.now(),
        randomBytes
      }),
    finishPasskeyRegistration: async input =>
      finishPasskeyRegistration({
        input,
        storage: options.storage,
        policy,
        now: () => clock.now()
      }),
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
            randomBytes
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
      rotateBackupCodes({
        input,
        storage: options.storage,
        policy,
        now: () => clock.now(),
        randomBytes,
        backupCodeHashSecret: options.backupCodeHashSecret
      }),
    redeemBackupCode: async input =>
      redeemBackupCode({
        input,
        storage: options.storage,
        now: () => clock.now(),
        backupCodeHashSecret: options.backupCodeHashSecret
      }),
    validateSession: async input =>
      validateSession({
        input,
        storage: options.storage,
        policy,
        now: () => clock.now(),
        hashSessionToken,
        createSessionToken
      }),
    revokeSession: async input =>
      revokeSession({
        input,
        storage: options.storage,
        now: () => clock.now(),
        hashSessionToken
      }),
    revokeAllUserSessions: async userId =>
      revokeAllUserSessions({
        userId,
        storage: options.storage,
        now: () => clock.now()
      }),
    startTotpEnrollment: async input => {
      if (!options.totpEncryptionKey)
        throw new AuthError('invalid_input', 'totpEncryptionKey is required');
      return startTotpEnrollment({
        input,
        storage: options.storage,
        policy,
        now: () => clock.now(),
        totpEncryptionKey: options.totpEncryptionKey,
        randomBytes
      });
    },
    finishTotpEnrollment: async input => {
      if (!options.totpEncryptionKey)
        throw new AuthError('invalid_input', 'totpEncryptionKey is required');
      return finishTotpEnrollment({
        input,
        storage: options.storage,
        policy,
        now: () => clock.now(),
        totpEncryptionKey: options.totpEncryptionKey
      });
    },
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
          createSessionToken
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
    challenge: { ...base.challenge, ...override.challenge }
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
}
