import type { ChallengeId, SessionTokenHash, UserId, WebAuthnCredentialId } from '../auth-types.js';
import type { AuthenticatorTransportFuture, CredentialDeviceType } from '@simplewebauthn/server';

export type ChallengeType = 'passkey_register' | 'passkey_login' | 'totp_pending';

export type StoredChallenge = {
  id: ChallengeId;
  type: ChallengeType;
  userId?: UserId;
  /**
   * Opaque, random, one-time challenge string.
   */
  challenge: string;
  expiresAt: Date;
};

export type SessionRecord = {
  /**
   * Store ONLY a hash (never store the raw session token).
   */
  tokenHash: SessionTokenHash;
  userId: UserId;
  createdAt: Date;
  lastSeenAt?: Date;
  expiresAt: Date;
  revokedAt?: Date;
  rotatedFromHash?: SessionTokenHash;
  /**
   * Optional session binding/device metadata (store only a hash; never store raw IP/UA if you can avoid it).
   */
  clientIdHash?: string;
  userAgentHash?: string;
};

export type WebAuthnCredentialRecord = {
  id: WebAuthnCredentialId;
  userId: UserId;
  /**
   * Base64url credential ID (same format used by SimpleWebAuthn and the browser JSON payloads).
   */
  credentialId: string;
  publicKey: Uint8Array;
  counter: number;
  transports?: AuthenticatorTransportFuture[];
  credentialDeviceType?: CredentialDeviceType;
  credentialBackedUp?: boolean;
  createdAt: Date;
  updatedAt?: Date;
};

export type BackupCodeRecord = {
  userId: UserId;
  /**
   * Hash of the backup code (never store plaintext).
   */
  codeHash: string;
  createdAt: Date;
  consumedAt?: Date;
};

export type PasswordCredentialRecord = {
  userId: UserId;
  /**
   * Versioned encoded password hash string (never store plaintext).
   * Example (PHC): "$argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>"
   */
  passwordHash: string;
  createdAt: Date;
  updatedAt?: Date;
};

/**
 * Storage interface. Apps implement this against their DB of choice.
 *
 * Important: operations that consume challenges/backup codes and rotate sessions
 * SHOULD be implemented atomically (transaction/compare-and-swap) to prevent reuse.
 */
export type AuthStorage = {
  users: {
    getUserIdByIdentifier(identifier: string): Promise<UserId | null>;
    /**
     * Create a new user with the given identifier.
     * Must enforce uniqueness of identifier.
     */
    createUser(identifier: string): Promise<UserId>;
  };

  passwordCredentials: {
    getForUser(userId: UserId): Promise<PasswordCredentialRecord | null>;
    upsertForUser(record: PasswordCredentialRecord): Promise<void>;
  };

  challenges: {
    createChallenge(challenge: StoredChallenge): Promise<void>;
    /**
     * Consume a challenge exactly once. Return it if found and not consumed.
     */
    consumeChallenge(id: ChallengeId): Promise<StoredChallenge | null>;
  };

  totp: {
    /**
     * Return the enabled TOTP record, if enabled for this user.
     */
    getEnabled(userId: UserId): Promise<{
      encryptedSecret: string;
      enabledAt: Date;
      /**
       * Timestamp of last accepted code (legacy; used for replay mitigation).
       */
      lastUsedAt?: Date;
      /**
       * Last accepted TOTP time-step (recommended). Enables atomic replay prevention.
       */
      lastUsedStep?: number;
    } | null>;
    /**
     * Return the pending secret awaiting verification, if any.
     */
    getPending(userId: UserId): Promise<{ encryptedSecret: string; createdAt: Date } | null>;
    /**
     * Store a pending secret awaiting verification.
     */
    setPending(userId: UserId, encryptedSecret: string, createdAt: Date): Promise<void>;
    /**
     * Enable pending secret (atomic). Should clear pending state.
     */
    enableFromPending(userId: UserId, enabledAt: Date): Promise<void>;
    disable(userId: UserId, disabledAt: Date): Promise<void>;
    updateLastUsedAt(userId: UserId, lastUsedAt: Date): Promise<void>;
    /**
     * Atomically prevent replay: set lastUsedStep iff it is strictly less than the provided step.
     *
     * Should be implemented as a compare-and-swap (e.g. SQL: UPDATE ... WHERE lastUsedStep < :step)
     * and return true only when the row was updated.
     *
     * If not implemented, core falls back to updateLastUsedAt() which is not race-free under concurrency.
     */
    updateLastUsedStepIfGreater?: (ctx: {
      userId: UserId;
      step: number;
      usedAt: Date;
    }) => Promise<boolean>;
  };

  sessions: {
    createSession(session: SessionRecord): Promise<void>;
    getSessionByTokenHash(tokenHash: SessionTokenHash): Promise<SessionRecord | null>;
    /**
     * List sessions for a user (for session management UI). Optional but recommended.
     */
    listSessionsForUser?: (userId: UserId) => Promise<SessionRecord[]>;
    /**
     * Update lastSeenAt (sliding session) without rotating the token.
     * Should be a no-op if the session doesn't exist or is revoked/expired (implementation-defined).
     */
    touchSession(tokenHash: SessionTokenHash, lastSeenAt: Date): Promise<void>;
    revokeSession(tokenHash: SessionTokenHash, revokedAt: Date): Promise<void>;
    revokeAllUserSessions(userId: UserId, revokedAt: Date): Promise<void>;
    /**
     * Revoke all sessions for a user except one (for "log out other devices"). Optional but recommended.
     */
    revokeAllUserSessionsExceptTokenHash?: (
      userId: UserId,
      exceptTokenHash: SessionTokenHash,
      revokedAt: Date
    ) => Promise<void>;
    /**
     * Rotate a session token atomically: insert new, revoke old.
     */
    rotateSession(
      oldTokenHash: SessionTokenHash,
      newSession: SessionRecord,
      revokedAt: Date
    ): Promise<void>;
  };

  webauthn: {
    listCredentialsForUser(userId: UserId): Promise<WebAuthnCredentialRecord[]>;
    getCredentialById(id: WebAuthnCredentialId): Promise<WebAuthnCredentialRecord | null>;
    createCredential(record: WebAuthnCredentialRecord): Promise<void>;
    updateCredentialCounter(
      id: WebAuthnCredentialId,
      counter: number,
      updatedAt: Date
    ): Promise<void>;
  };

  backupCodes: {
    /**
     * Replace all backup codes for a user (rotation). Should be atomic.
     */
    replaceCodes(userId: UserId, codes: BackupCodeRecord[], rotatedAt: Date): Promise<void>;
    /**
     * Consume a backup code exactly once. Should be atomic.
     */
    consumeCode(userId: UserId, codeHash: string, consumedAt: Date): Promise<boolean>;
    countRemaining(userId: UserId): Promise<number>;
  };
};
