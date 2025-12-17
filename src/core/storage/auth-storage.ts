import type { ChallengeId, SessionTokenHash, UserId, WebAuthnCredentialId } from "../auth-types.js";
import type { AuthenticatorTransportFuture, CredentialDeviceType } from "@simplewebauthn/server";

export type ChallengeType = "passkey_register" | "passkey_login";

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

  sessions: {
    createSession(session: SessionRecord): Promise<void>;
    getSessionByTokenHash(tokenHash: SessionTokenHash): Promise<SessionRecord | null>;
    revokeSession(tokenHash: SessionTokenHash, revokedAt: Date): Promise<void>;
    revokeAllUserSessions(userId: UserId, revokedAt: Date): Promise<void>;
    /**
     * Rotate a session token atomically: insert new, revoke old.
     */
    rotateSession(oldTokenHash: SessionTokenHash, newSession: SessionRecord, revokedAt: Date): Promise<void>;
  };

  webauthn: {
    listCredentialsForUser(userId: UserId): Promise<WebAuthnCredentialRecord[]>;
    getCredentialById(id: WebAuthnCredentialId): Promise<WebAuthnCredentialRecord | null>;
    createCredential(record: WebAuthnCredentialRecord): Promise<void>;
    updateCredentialCounter(id: WebAuthnCredentialId, counter: number, updatedAt: Date): Promise<void>;
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


