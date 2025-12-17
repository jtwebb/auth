import type {
  AuthenticationResponseJSON,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON,
} from "@simplewebauthn/server";
import type { ChallengeId, CreateSessionTokenResult, UserId, WebAuthnCredentialId } from "../auth-types.js";

export type PasskeyRegistrationStartInput = {
  userId: UserId;
  userName: string;
  userDisplayName?: string;
};

export type PasskeyRegistrationStartResult = {
  challengeId: ChallengeId;
  options: PublicKeyCredentialCreationOptionsJSON;
};

export type PasskeyRegistrationFinishInput = {
  userId: UserId;
  challengeId: ChallengeId;
  response: RegistrationResponseJSON;
};

export type PasskeyRegistrationFinishResult = {
  userId: UserId;
  credentialId: WebAuthnCredentialId;
};

export type PasskeyLoginStartInput = {
  /**
   * If provided, constrain to this user's credentials (classic UX).
   * If omitted, we do discoverable (passkey-first) login.
   */
  userId?: UserId;
};

export type PasskeyLoginStartResult = {
  challengeId: ChallengeId;
  options: PublicKeyCredentialRequestOptionsJSON;
};

export type PasskeyLoginFinishInput = {
  challengeId: ChallengeId;
  response: AuthenticationResponseJSON;
};

export type PasskeyLoginFinishResult = {
  userId: UserId;
  session: CreateSessionTokenResult;
};


