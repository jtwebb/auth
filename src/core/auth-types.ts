export type Brand<T, B extends string> = T & { readonly __brand: B };

export type UserId = Brand<string, 'UserId'>;
export type SessionToken = Brand<string, 'SessionToken'>;
export type SessionTokenHash = Brand<string, 'SessionTokenHash'>;
export type ChallengeId = Brand<string, 'ChallengeId'>;
export type WebAuthnCredentialId = Brand<string, 'WebAuthnCredentialId'>;
export type PasswordResetToken = Brand<string, 'PasswordResetToken'>;
export type PasswordResetTokenHash = Brand<string, 'PasswordResetTokenHash'>;

export type CreateSessionTokenResult = {
  sessionToken: SessionToken;
  sessionTokenHash: SessionTokenHash;
};

export type SessionContextInput = {
  /**
   * Stable client identifier (e.g. IP or device id) as seen by your server.
   * Prefer using a trusted value from your edge/proxy, not user-provided fields.
   */
  clientId?: string;
  /**
   * User-Agent header value.
   */
  userAgent?: string;
};

export type PasswordLoginInput = {
  /**
   * Identifier (email/username). Keep generic; adapters can normalize.
   */
  identifier: string;
  password: string;
  /**
   * Optional context used for session binding / device metadata.
   */
  sessionContext?: SessionContextInput;
};

export type PasswordLoginResult =
  | { twoFactorRequired: true; userId: UserId; pendingToken: ChallengeId }
  | { twoFactorRequired?: false; userId: UserId; session: CreateSessionTokenResult };

export type PasswordRegisterInput = {
  identifier: string;
  password: string;
  /**
   * Optional context used for session binding / device metadata.
   */
  sessionContext?: SessionContextInput;
};

export type PasswordRegisterResult = {
  userId: UserId;
  session: CreateSessionTokenResult;
};
