import type { CreateSessionTokenResult, SessionToken, UserId } from "../auth-types.js";

export type ValidateSessionInput = {
  sessionToken: SessionToken;
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
      reason: "missing" | "revoked" | "expired";
    };

export type RevokeSessionInput = {
  sessionToken: SessionToken;
};

export type RevokeSessionResult = { ok: true };


