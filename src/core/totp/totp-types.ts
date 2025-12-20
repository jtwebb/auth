import type {
  ChallengeId,
  CreateSessionTokenResult,
  SessionContextInput,
  UserId
} from '../auth-types.js';

export type StartTotpEnrollmentInput = {
  userId: UserId;
  /**
   * Account label shown in authenticator apps (usually email/username).
   */
  accountName: string;
};

export type StartTotpEnrollmentResult = {
  userId: UserId;
  secretBase32: string;
  otpauthUri: string;
};

export type FinishTotpEnrollmentInput = {
  userId: UserId;
  code: string;
};

export type FinishTotpEnrollmentResult = { enabled: true };

export type VerifyTotpInput = {
  pendingToken: ChallengeId;
  code: string;
  /**
   * Optional context used for session binding / device metadata.
   */
  sessionContext?: SessionContextInput;
};

export type VerifyTotpResult = {
  userId: UserId;
  session: CreateSessionTokenResult;
};
