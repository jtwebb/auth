export type FetchLike = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;

export type AuthApiError = {
  error: { code: string; message: string };
};

export type PasskeyRegistrationStartPayload = {
  userId: string;
  userName: string;
  userDisplayName?: string;
};

export type PasskeyRegistrationStartResult = {
  challengeId: string;
  options: any;
};

export type PasskeyRegistrationFinishPayload = {
  userId: string;
  challengeId: string;
  response: any;
};

export type PasskeyLoginStartPayload = {
  userId?: string;
};

export type PasskeyLoginStartResult = {
  challengeId: string;
  options: any;
};

export type PasskeyLoginFinishPayload = {
  challengeId: string;
  response: any;
};

export type BackupCodeRedeemPayload = {
  userId: string;
  code: string;
};


