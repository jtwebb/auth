import type { AuthCore } from "../../core/create-auth-core.js";
import { AuthError, isAuthError } from "../../core/auth-error.js";
import type { SessionToken } from "../../core/auth-types.js";
import type { ValidateSessionResult } from "../../core/sessions/session-types.js";
import type { CookieOptions } from "./cookies.js";
import { getCookie, serializeCookie, serializeDeleteCookie } from "./cookies.js";
import { assertSameOrigin, json, readForm, readJson, redirect } from "./http.js";

export type ReactRouterAuthAdapterOptions = {
  core: AuthCore;
  /**
   * Cookie configuration for transporting the session token.
   */
  sessionCookie: CookieOptions;
  /**
   * CSRF/origin checks for state-changing actions. Defaults to core policy origins.
   */
  csrf?: {
    enabled?: boolean;
    allowedOrigins?: readonly string[];
  };
};

export type RequireUserResult = {
  userId: string;
  /**
   * Headers to apply to the response (e.g. Set-Cookie after rotation).
   */
  headers: Headers;
};

export type ReactRouterAuthAdapter = {
  /**
   * Read session cookie and validate it. Returns rotation headers if needed.
   */
  validate(request: Request): Promise<{ result: ValidateSessionResult; headers: Headers }>;
  /**
   * Require an authenticated user, otherwise throw a redirect response.
   */
  requireUser(request: Request, opts?: { redirectTo?: string }): Promise<RequireUserResult>;
  /**
   * Logout (revoke server-side and clear cookie).
   */
  logout(request: Request, opts?: { redirectTo?: string }): Promise<Response>;

  actions: {
    passwordLogin(request: Request, opts?: { redirectTo?: string }): Promise<Response>;
    passwordRegister(request: Request, opts?: { redirectTo?: string }): Promise<Response>;

    passkeyRegistrationStart(request: Request): Promise<Response>;
    passkeyRegistrationFinish(request: Request, opts?: { redirectTo?: string }): Promise<Response>;
    passkeyLoginStart(request: Request): Promise<Response>;
    passkeyLoginFinish(request: Request, opts?: { redirectTo?: string }): Promise<Response>;
  };
};

export function createReactRouterAuthAdapter(options: ReactRouterAuthAdapterOptions): ReactRouterAuthAdapter {
  const allowedOrigins = options.csrf?.allowedOrigins ?? options.core.policy.passkey.origins;
  const csrfEnabled = options.csrf?.enabled ?? true;

  const validate = async (request: Request) => {
    const headers = new Headers();
    const token = getCookie(request, options.sessionCookie.name);
    if (!token) return { result: { ok: false, reason: "missing" } as const, headers };

    const result = await options.core.validateSession({ sessionToken: token as unknown as SessionToken });
    if (result.ok && result.rotatedSession) {
      headers.append(
        "set-cookie",
        serializeCookie(options.sessionCookie.name, result.rotatedSession.sessionToken as unknown as string, {
          ...options.sessionCookie,
        }),
      );
    }
    return { result, headers };
  };

  const requireUser = async (request: Request, opts: { redirectTo?: string } = {}): Promise<RequireUserResult> => {
    const { result, headers } = await validate(request);
    if (!result.ok) {
      throw redirect(opts.redirectTo ?? "/login");
    }
    return { userId: result.userId as unknown as string, headers };
  };

  const logout = async (request: Request, opts: { redirectTo?: string } = {}): Promise<Response> => {
    if (csrfEnabled) assertSameOrigin(request, allowedOrigins);
    const token = getCookie(request, options.sessionCookie.name);
    if (token) await options.core.revokeSession({ sessionToken: token as unknown as SessionToken });
    const res = redirect(opts.redirectTo ?? "/login");
    res.headers.append("set-cookie", serializeDeleteCookie(options.sessionCookie.name, { ...options.sessionCookie }));
    return res;
  };

  const passwordLogin = async (request: Request, opts: { redirectTo?: string } = {}): Promise<Response> => {
    if (csrfEnabled) assertSameOrigin(request, allowedOrigins);
    try {
      const form = await readForm(request);
      const identifier = String(form.get("identifier") ?? "");
      const password = String(form.get("password") ?? "");
      const { session } = await options.core.loginPassword({ identifier, password });
      const res = redirect(opts.redirectTo ?? "/");
      res.headers.append(
        "set-cookie",
        serializeCookie(options.sessionCookie.name, session.sessionToken as unknown as string, { ...options.sessionCookie }),
      );
      return res;
    } catch (err) {
      return mapAuthError(err);
    }
  };

  const passwordRegister = async (request: Request, opts: { redirectTo?: string } = {}): Promise<Response> => {
    if (csrfEnabled) assertSameOrigin(request, allowedOrigins);
    try {
      const form = await readForm(request);
      const identifier = String(form.get("identifier") ?? "");
      const password = String(form.get("password") ?? "");
      const { session } = await options.core.registerPassword({ identifier, password });
      const res = redirect(opts.redirectTo ?? "/");
      res.headers.append(
        "set-cookie",
        serializeCookie(options.sessionCookie.name, session.sessionToken as unknown as string, { ...options.sessionCookie }),
      );
      return res;
    } catch (err) {
      return mapAuthError(err);
    }
  };

  const passkeyRegistrationStart = async (request: Request): Promise<Response> => {
    if (csrfEnabled) assertSameOrigin(request, allowedOrigins);
    try {
      const body = await readJson<{ userId: string; userName: string; userDisplayName?: string }>(request);
      const out = await options.core.startPasskeyRegistration({
        userId: body.userId as any,
        userName: body.userName,
        userDisplayName: body.userDisplayName,
      });
      return json(out);
    } catch (err) {
      return mapAuthError(err);
    }
  };

  const passkeyRegistrationFinish = async (request: Request, opts: { redirectTo?: string } = {}): Promise<Response> => {
    if (csrfEnabled) assertSameOrigin(request, allowedOrigins);
    try {
      const body = await readJson<any>(request);
      await options.core.finishPasskeyRegistration({
        userId: body.userId as any,
        challengeId: body.challengeId as any,
        response: body.response,
      });
      return redirect(opts.redirectTo ?? "/");
    } catch (err) {
      return mapAuthError(err);
    }
  };

  const passkeyLoginStart = async (request: Request): Promise<Response> => {
    if (csrfEnabled) assertSameOrigin(request, allowedOrigins);
    try {
      const body = await readJson<{ userId?: string }>(request);
      const out = await options.core.startPasskeyLogin({ userId: body.userId as any });
      return json(out);
    } catch (err) {
      return mapAuthError(err);
    }
  };

  const passkeyLoginFinish = async (request: Request, opts: { redirectTo?: string } = {}): Promise<Response> => {
    if (csrfEnabled) assertSameOrigin(request, allowedOrigins);
    try {
      const body = await readJson<any>(request);
      const out = await options.core.finishPasskeyLogin({
        challengeId: body.challengeId as any,
        response: body.response,
      });
      const res = redirect(opts.redirectTo ?? "/");
      res.headers.append(
        "set-cookie",
        serializeCookie(options.sessionCookie.name, out.session.sessionToken as unknown as string, { ...options.sessionCookie }),
      );
      return res;
    } catch (err) {
      return mapAuthError(err);
    }
  };

  return {
    validate,
    requireUser,
    logout,
    actions: {
      passwordLogin,
      passwordRegister,
      passkeyRegistrationStart,
      passkeyRegistrationFinish,
      passkeyLoginStart,
      passkeyLoginFinish,
    },
  };
}

function mapAuthError(err: unknown): Response {
  if (isAuthError(err)) {
    return json(
      {
        error: {
          code: err.code,
          message: err.publicMessage ?? "Request failed",
        },
      },
      { status: err.status },
    );
  }
  const unknown = new AuthError("internal_error", "Unexpected error", { publicMessage: "Request failed", status: 500, cause: err });
  return json(
    {
      error: {
        code: unknown.code,
        message: unknown.publicMessage,
      },
    },
    { status: unknown.status },
  );
}


