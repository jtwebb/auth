import type {
  CreateSessionTokenResult,
  SessionContextInput,
  SessionToken,
  UserId
} from '../auth-types.js';

export type ValidateSessionInput = {
  sessionToken: SessionToken;
  /**
   * Optional context for session binding checks.
   */
  sessionContext?: SessionContextInput;
};

export type ValidateSessionResult =
  | {
      ok: true;
      userId: UserId;
      /**
       * When present, the caller should set the new token in the cookie (rotation).
       */
      rotatedSession?: CreateSessionTokenResult;
    }
  | {
      ok: false;
      reason: 'missing' | 'revoked' | 'expired' | 'invalid';
    };

export type RevokeSessionInput = {
  sessionToken: SessionToken;
};

export type RevokeSessionResult = { ok: true };
