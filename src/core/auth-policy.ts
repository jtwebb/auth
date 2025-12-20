export type UserVerificationPolicy = 'required' | 'preferred' | 'discouraged';

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
  /**
   * Reduce write amplification: only "touch" lastSeenAt at most this often.
   * Set to 0 to touch on every request.
   */
  touchEveryMs?: number;
  /**
   * Optional session binding. When enabled, validation will reject sessions when the bound context
   * does not match (e.g. different user agent or client id).
   *
   * Note: binding is environment-dependent; keep disabled by default.
   */
  bindTo?: {
    clientId?: boolean;
    userAgent?: boolean;
  };
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
  totp: TotpPolicy;
  session: SessionPolicy;
  challenge: ChallengePolicy;
};

export type TotpPolicy = {
  issuer: string;
  digits: 6 | 8;
  periodSeconds: 30 | 60;
  /**
   * Accept codes from +/- this many time-steps to handle minor clock skew.
   */
  allowedSkewSteps: number;
};

export const defaultAuthPolicy: AuthPolicy = {
  password: {
    minLength: 12,
    maxLength: 1024
  },
  passkey: {
    rpId: 'localhost',
    rpName: 'localhost',
    origins: ['http://localhost:5173'],
    userVerification: 'preferred'
  },
  backupCodes: {
    count: 10,
    length: 10
  },
  totp: {
    issuer: 'localhost',
    digits: 6,
    periodSeconds: 30,
    allowedSkewSteps: 1
  },
  session: {
    absoluteTtlMs: 1000 * 60 * 60 * 24 * 30, // 30d
    idleTtlMs: 1000 * 60 * 60 * 24 * 7, // 7d
    rotateEveryMs: 1000 * 60 * 60 * 24, // 24h
    touchEveryMs: 1000 * 60 * 5 // 5m
  },
  challenge: {
    ttlMs: 1000 * 60 * 5 // 5m
  }
};
