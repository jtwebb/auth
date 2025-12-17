export type AuthErrorCode =
  | "not_implemented"
  | "invalid_input"
  | "unauthorized"
  | "forbidden"
  | "rate_limited"
  | "conflict"
  | "not_found"
  | "internal_error"
  // Future-facing auth-specific codes (we'll implement in later milestones)
  | "password_invalid"
  | "passkey_invalid"
  | "challenge_invalid"
  | "challenge_expired"
  | "backup_code_invalid"
  | "backup_code_consumed"
  | "two_factor_required"
  | "totp_invalid"
  | "totp_not_enabled";

export type AuthErrorOptions = {
  cause?: unknown;
  /**
   * Safe-to-expose message intended for UI/clients.
   * Prefer generic messages to avoid user enumeration.
   */
  publicMessage?: string;
  /**
   * Optional HTTP-ish status mapping for adapters.
   */
  status?: number;
};

export class AuthError extends Error {
  public readonly code: AuthErrorCode;
  public readonly publicMessage?: string;
  public readonly status: number;

  constructor(code: AuthErrorCode, message: string, options: AuthErrorOptions = {}) {
    super(message, { cause: options.cause });
    this.name = "AuthError";
    this.code = code;
    this.publicMessage = options.publicMessage;
    this.status = options.status ?? defaultStatusForCode(code);
  }
}

export function isAuthError(err: unknown): err is AuthError {
  return err instanceof AuthError;
}

export function defaultStatusForCode(code: AuthErrorCode): number {
  switch (code) {
    case "invalid_input":
      return 400;
    case "unauthorized":
    case "password_invalid":
    case "passkey_invalid":
    case "backup_code_invalid":
    case "backup_code_consumed":
    case "challenge_invalid":
    case "challenge_expired":
    case "totp_invalid":
      return 401;
    case "forbidden":
      return 403;
    case "not_found":
      return 404;
    case "conflict":
      return 409;
    case "rate_limited":
      return 429;
    case "not_implemented":
      return 501;
    case "internal_error":
    default:
      return 500;
  }
}


