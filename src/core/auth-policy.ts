export type UserVerificationPolicy = "required" | "preferred" | "discouraged";

export type PasswordPolicy = {
  /**
   * Keep rules simple: require long passwords, avoid composition rules.
   */
  minLength: number;
  maxLength: number;
};

export type PasskeyPolicy = {
  /**
   * Relying Party ID (usually your domain).
   * Example: "example.com"
   */
  rpId: string;
  /**
   * Human-friendly RP name shown in browser passkey UI.
   */
  rpName: string;
  /**
   * Allowed origins.
   * Example: ["https://example.com", "https://www.example.com"]
   */
  origins: readonly string[];
  userVerification: UserVerificationPolicy;
};

export type BackupCodePolicy = {
  /**
   * Number of codes to generate per rotation.
   */
  count: number;
  /**
   * Number of characters per code (implementation-defined encoding).
   */
  length: number;
};

export type SessionPolicy = {
  /**
   * Absolute lifetime in milliseconds.
   */
  absoluteTtlMs: number;
  /**
   * Idle timeout in milliseconds (sliding expiration). Optional.
   */
  idleTtlMs?: number;
  /**
   * Rotate tokens at most this often (sliding). Optional.
   */
  rotateEveryMs?: number;
};

export type ChallengePolicy = {
  /**
   * TTL for WebAuthn challenges in milliseconds.
   */
  ttlMs: number;
};

export type AuthPolicy = {
  password: PasswordPolicy;
  passkey: PasskeyPolicy;
  backupCodes: BackupCodePolicy;
  session: SessionPolicy;
  challenge: ChallengePolicy;
};

export const defaultAuthPolicy: AuthPolicy = {
  password: {
    minLength: 12,
    maxLength: 1024,
  },
  passkey: {
    rpId: "localhost",
    rpName: "localhost",
    origins: ["http://localhost:5173"],
    userVerification: "preferred",
  },
  backupCodes: {
    count: 10,
    length: 10,
  },
  session: {
    absoluteTtlMs: 1000 * 60 * 60 * 24 * 30, // 30d
    idleTtlMs: 1000 * 60 * 60 * 24 * 7, // 7d
    rotateEveryMs: 1000 * 60 * 60 * 24, // 24h
  },
  challenge: {
    ttlMs: 1000 * 60 * 5, // 5m
  },
};


