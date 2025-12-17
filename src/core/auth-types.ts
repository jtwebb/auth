export type Brand<T, B extends string> = T & { readonly __brand: B };

export type UserId = Brand<string, 'UserId'>;
export type SessionToken = Brand<string, 'SessionToken'>;
export type SessionTokenHash = Brand<string, 'SessionTokenHash'>;
export type ChallengeId = Brand<string, 'ChallengeId'>;
export type WebAuthnCredentialId = Brand<string, 'WebAuthnCredentialId'>;

export type CreateSessionTokenResult = {
  sessionToken: SessionToken;
  sessionTokenHash: SessionTokenHash;
};

export type PasswordLoginInput = {
  /**
   * Identifier (email/username). Keep generic; adapters can normalize.
   */
  identifier: string;
  password: string;
};

export type PasswordLoginResult =
  | { twoFactorRequired: true; userId: UserId; pendingToken: ChallengeId }
  | { twoFactorRequired?: false; userId: UserId; session: CreateSessionTokenResult };

export type PasswordRegisterInput = {
  identifier: string;
  password: string;
};

export type PasswordRegisterResult = {
  userId: UserId;
  session: CreateSessionTokenResult;
};
