import type { UserId } from "../auth-types.js";

export type RotateBackupCodesInput = {
  userId: UserId;
};

export type RotateBackupCodesResult = {
  userId: UserId;
  /**
   * Plaintext codes (display once). These MUST NOT be stored or logged.
   */
  codes: string[];
};

export type RedeemBackupCodeInput = {
  userId: UserId;
  code: string;
};

export type RedeemBackupCodeResult = {
  userId: UserId;
  remaining: number;
};


