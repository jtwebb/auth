import type { AuthCore } from '../../core/create-auth-core.js';
import { AuthError, isAuthError } from '../../core/auth-error.js';
import type { ChallengeId, SessionToken, UserId } from '../../core/auth-types.js';
import type { ValidateSessionResult } from '../../core/sessions/session-types.js';
import {
  InMemoryProgressiveDelay,
  InMemoryRateLimiter,
  type ProgressiveDelayRule,
  type RateLimitRule
} from '../../core/rate-limit.js';
import type {
  PasskeyLoginFinishInput,
  PasskeyRegistrationFinishInput
} from '../../core/passkey/passkey-types.js';
import { randomBytes } from 'node:crypto';
import type { CookieOptions } from './cookies.js';
import { getCookie, serializeCookie, serializeDeleteCookie } from './cookies.js';
import { assertSameOrigin, json, readForm, readJson, redirect } from './http.js';

export type ReactRouterAuthAdapterOptions = {
  core: AuthCore;
  /**
   * Cookie configuration for transporting the session token.
   */
  sessionCookie: CookieOptions;
  /**
   * Cookie configuration for transporting the pending TOTP token during step-up.
   */
  totpPendingCookie?: CookieOptions;
  /**
   * Where to send the user when 2FA is required.
   */
  twoFactorRedirectTo?: string;
  /**
   * CSRF/origin checks for state-changing actions. Defaults to core policy origins.
   */
  csrf?: {
    enabled?: boolean;
    allowedOrigins?: readonly string[];
    /**
     * If true, allow requests with missing Origin/Referer (useful for non-browser clients).
     * Defaults to false (stricter).
     */
    allowMissingOrigin?: boolean;
    /**
     * Double-submit CSRF protection (cookie + header/form field). Enabled by default.
     *
     * You must mint a CSRF cookie token on a GET/loader route by calling `auth.csrf.getToken(request)`
     * and adding the returned headers to your response, then include the token in subsequent POSTs.
     */
    doubleSubmit?: {
      enabled?: boolean;
      /**
       * CSRF token cookie configuration. Must NOT be HttpOnly (so browser JS can read it for fetch),
       * or you must embed it into a form field server-side.
       */
      cookie?: CookieOptions;
      /**
       * Header name for fetch/XHR clients.
       */
      headerName?: string;
      /**
       * Form field name for non-JS form POSTs.
       */
      formFieldName?: string;
      /**
       * Optional JSON field name if clients submit token in JSON bodies.
       */
      jsonFieldName?: string;
    };
  };
  /**
   * Basic rate limiting for auth endpoints. Enabled by default.
   *
   * Note: the default limiter is in-memory (single-instance). For multi-instance deployments,
   * provide your own limiter or enforce limits at the edge (CDN/WAF) / shared store.
   */
  rateLimit?: {
    enabled?: boolean;
    /**
     * Custom limiter implementation. Defaults to a new InMemoryRateLimiter().
     */
    limiter?: Pick<InMemoryRateLimiter, 'consume'>;
    /**
     * Extract a client identifier (e.g. IP) from the request for per-client limits.
     * If it returns null/empty, per-client limits are skipped.
     */
    getClientId?: (request: Request) => string | null;
    rules?: Partial<ReactRouterAuthRateLimitRules>;
    /**
     * Progressive delays + temporary lockouts that reset on success.
     * Enabled by default.
     */
    progressiveDelay?: {
      enabled?: boolean;
      /**
       * Custom progressive delay store. Defaults to a new InMemoryProgressiveDelay().
       */
      store?: Pick<InMemoryProgressiveDelay, 'check' | 'recordFailure' | 'recordSuccess'>;
      rules?: Partial<ReactRouterAuthProgressiveDelayRules>;
    };
  };
};

export type ReactRouterAuthRateLimitRules = {
  passwordLoginPerIdentifier: RateLimitRule;
  passwordLoginPerClient: RateLimitRule;
  totpVerifyPerPending: RateLimitRule;
  totpVerifyPerClient: RateLimitRule;
  passkeyFinishPerChallenge: RateLimitRule;
  passkeyFinishPerClient: RateLimitRule;
};

export type ReactRouterAuthProgressiveDelayRules = {
  passwordLoginPerIdentifier: ProgressiveDelayRule;
  passwordLoginPerClient: ProgressiveDelayRule;
  totpVerifyPerPending: ProgressiveDelayRule;
  totpVerifyPerClient: ProgressiveDelayRule;
  passkeyFinishPerChallenge: ProgressiveDelayRule;
  passkeyFinishPerClient: ProgressiveDelayRule;
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
  /**
   * CSRF helper for browser apps (double-submit).
   */
  csrf: {
    /**
     * Get or mint a CSRF token cookie for the current client.
     * Add the returned headers to your loader response and include the token in subsequent POSTs
     * (header or form field).
     */
    getToken(request: Request): { token: string; headers: Headers };
  };

  actions: {
    passwordLogin(request: Request, opts?: { redirectTo?: string }): Promise<Response>;
    passwordRegister(request: Request, opts?: { redirectTo?: string }): Promise<Response>;

    passkeyRegistrationStart(request: Request): Promise<Response>;
    passkeyRegistrationFinish(request: Request, opts?: { redirectTo?: string }): Promise<Response>;
    passkeyLoginStart(request: Request): Promise<Response>;
    passkeyLoginFinish(request: Request, opts?: { redirectTo?: string }): Promise<Response>;
    totpEnrollmentStart(request: Request): Promise<Response>;
    totpEnrollmentFinish(request: Request, opts?: { redirectTo?: string }): Promise<Response>;
    totpVerify(request: Request, opts?: { redirectTo?: string }): Promise<Response>;
  };
};

export function createReactRouterAuthAdapter(
  options: ReactRouterAuthAdapterOptions
): ReactRouterAuthAdapter {
  const allowedOrigins = options.csrf?.allowedOrigins ?? options.core.policy.passkey.origins;
  const csrfEnabled = options.csrf?.enabled ?? true;
  const csrfAllowMissingOrigin = options.csrf?.allowMissingOrigin ?? false;
  const csrfDoubleSubmitEnabled = options.csrf?.doubleSubmit?.enabled ?? true;
  const csrfTokenCookie: CookieOptions = options.csrf?.doubleSubmit?.cookie ?? {
    name: 'csrf',
    path: '/',
    httpOnly: false,
    secure: true,
    sameSite: 'strict'
  };
  const csrfHeaderName = (options.csrf?.doubleSubmit?.headerName ?? 'x-csrf-token').toLowerCase();
  const csrfFormFieldName = options.csrf?.doubleSubmit?.formFieldName ?? 'csrfToken';
  const totpPendingCookie: CookieOptions = options.totpPendingCookie ?? {
    name: 'totp',
    path: '/',
    httpOnly: true,
    secure: true,
    sameSite: 'lax',
    maxAgeSeconds: 60 * 5
  };
  const twoFactorRedirectTo = options.twoFactorRedirectTo ?? '/two-factor';

  const rateLimitEnabled = options.rateLimit?.enabled ?? true;
  const limiter: Pick<InMemoryRateLimiter, 'consume'> =
    options.rateLimit?.limiter ?? new InMemoryRateLimiter();
  const getClientId =
    options.rateLimit?.getClientId ??
    ((request: Request) => {
      const cf = request.headers.get('cf-connecting-ip');
      if (cf) return cf.trim();
      const xff = request.headers.get('x-forwarded-for');
      if (xff) return xff.split(',')[0]?.trim() ?? null;
      const xri = request.headers.get('x-real-ip');
      if (xri) return xri.trim();
      return null;
    });
  const rules: ReactRouterAuthRateLimitRules = {
    // Defaults are intentionally conservative and intended to be safe across many apps.
    passwordLoginPerIdentifier: { windowMs: 15 * 60_000, max: 10 },
    passwordLoginPerClient: { windowMs: 15 * 60_000, max: 100 },
    totpVerifyPerPending: { windowMs: 5 * 60_000, max: 10 },
    totpVerifyPerClient: { windowMs: 5 * 60_000, max: 50 },
    passkeyFinishPerChallenge: { windowMs: 5 * 60_000, max: 20 },
    passkeyFinishPerClient: { windowMs: 5 * 60_000, max: 100 },
    ...(options.rateLimit?.rules ?? {})
  };

  const enforceRateLimit = (key: string, rule: RateLimitRule) => {
    if (!rateLimitEnabled) return;
    const res = limiter.consume(key, rule);
    if (res.ok) return;
    const seconds = Math.max(1, Math.ceil(res.retryAfterMs / 1000));
    throw new AuthError('rate_limited', 'Too many attempts', {
      status: 429,
      publicMessage: `Too many attempts. Try again in ${seconds} seconds.`,
      cause: { retryAfterMs: res.retryAfterMs }
    });
  };

  const progressiveDelayEnabled = options.rateLimit?.progressiveDelay?.enabled ?? true;
  const progressiveStore: Pick<
    InMemoryProgressiveDelay,
    'check' | 'recordFailure' | 'recordSuccess'
  > = options.rateLimit?.progressiveDelay?.store ?? new InMemoryProgressiveDelay();
  const progressiveRules: ReactRouterAuthProgressiveDelayRules = {
    passwordLoginPerIdentifier: {
      failureWindowMs: 15 * 60_000,
      startAfterFailures: 3,
      baseDelayMs: 1_000,
      factor: 2,
      maxDelayMs: 60_000,
      lockoutAfterFailures: 10,
      lockoutMs: 15 * 60_000
    },
    passwordLoginPerClient: {
      failureWindowMs: 15 * 60_000,
      startAfterFailures: 10,
      baseDelayMs: 500,
      factor: 2,
      maxDelayMs: 60_000,
      lockoutAfterFailures: 50,
      lockoutMs: 15 * 60_000
    },
    totpVerifyPerPending: {
      failureWindowMs: 5 * 60_000,
      startAfterFailures: 3,
      baseDelayMs: 1_000,
      factor: 2,
      maxDelayMs: 30_000,
      lockoutAfterFailures: 10,
      lockoutMs: 5 * 60_000
    },
    totpVerifyPerClient: {
      failureWindowMs: 5 * 60_000,
      startAfterFailures: 10,
      baseDelayMs: 500,
      factor: 2,
      maxDelayMs: 30_000,
      lockoutAfterFailures: 50,
      lockoutMs: 5 * 60_000
    },
    passkeyFinishPerChallenge: {
      failureWindowMs: 5 * 60_000,
      startAfterFailures: 10,
      baseDelayMs: 250,
      factor: 2,
      maxDelayMs: 10_000,
      lockoutAfterFailures: 100,
      lockoutMs: 5 * 60_000
    },
    passkeyFinishPerClient: {
      failureWindowMs: 5 * 60_000,
      startAfterFailures: 20,
      baseDelayMs: 250,
      factor: 2,
      maxDelayMs: 10_000,
      lockoutAfterFailures: 200,
      lockoutMs: 5 * 60_000
    },
    ...(options.rateLimit?.progressiveDelay?.rules ?? {})
  };

  const enforceProgressiveDelay = (key: string) => {
    if (!rateLimitEnabled || !progressiveDelayEnabled) return;
    const status = progressiveStore.check(key);
    if (status.ok) return;
    const seconds = Math.max(1, Math.ceil(status.retryAfterMs / 1000));
    throw new AuthError('rate_limited', 'Too many attempts', {
      status: 429,
      publicMessage: `Too many attempts. Try again in ${seconds} seconds.`,
      cause: { retryAfterMs: status.retryAfterMs }
    });
  };

  const recordFailure = (key: string, rule: ProgressiveDelayRule) => {
    if (!rateLimitEnabled || !progressiveDelayEnabled) return;
    progressiveStore.recordFailure(key, rule);
  };

  const recordSuccess = (key: string) => {
    if (!rateLimitEnabled || !progressiveDelayEnabled) return;
    progressiveStore.recordSuccess(key);
  };

  const csrfCheckOrigin = (request: Request) => {
    if (!csrfEnabled) return;
    assertSameOrigin(request, allowedOrigins, { allowMissingOrigin: csrfAllowMissingOrigin });
  };

  const base64UrlEncode = (bytes: Uint8Array): string =>
    Buffer.from(bytes)
      .toString('base64')
      .replaceAll('+', '-')
      .replaceAll('/', '_')
      .replaceAll('=', '');

  const getOrCreateCsrfToken = (request: Request): { token: string; headers: Headers } => {
    const headers = new Headers();
    const existing = getCookie(request, csrfTokenCookie.name);
    if (typeof existing === 'string' && existing.length >= 16) {
      return { token: existing, headers };
    }
    const token = base64UrlEncode(randomBytes(32));
    headers.append(
      'set-cookie',
      serializeCookie(csrfTokenCookie.name, token, {
        ...csrfTokenCookie,
        // Ensure it's readable by JS if clients use header-based submit.
        httpOnly: false
      })
    );
    return { token, headers };
  };

  const assertDoubleSubmitCsrf = (request: Request, providedToken?: string | null): void => {
    if (!csrfEnabled || !csrfDoubleSubmitEnabled) return;
    const cookieToken = getCookie(request, csrfTokenCookie.name);
    const tokenFromCookie = typeof cookieToken === 'string' ? cookieToken : null;
    const tokenFromProvided =
      typeof providedToken === 'string' && providedToken.trim() ? providedToken.trim() : null;
    const tokenFromHeader = (() => {
      const v = request.headers.get(csrfHeaderName);
      return v && v.trim() ? v.trim() : null;
    })();
    const token = tokenFromProvided ?? tokenFromHeader;
    if (!tokenFromCookie || !token) {
      throw new AuthError('forbidden', 'CSRF protection: missing token', {
        status: 403,
        publicMessage: 'Forbidden'
      });
    }
    if (token !== tokenFromCookie) {
      throw new AuthError('forbidden', 'CSRF protection: invalid token', {
        status: 403,
        publicMessage: 'Forbidden'
      });
    }
  };

  const sessionContextFromRequest = (request: Request) => ({
    clientId: getClientId(request) ?? undefined,
    userAgent: request.headers.get('user-agent') ?? undefined
  });

  const validate = async (request: Request) => {
    const headers = new Headers();
    const token = getCookie(request, options.sessionCookie.name);
    if (!token) return { result: { ok: false, reason: 'missing' } as const, headers };

    const result = await options.core.validateSession({
      sessionToken: token as unknown as SessionToken,
      sessionContext: sessionContextFromRequest(request)
    });
    if (result.ok && result.rotatedSession) {
      headers.append(
        'set-cookie',
        serializeCookie(
          options.sessionCookie.name,
          result.rotatedSession.sessionToken as unknown as string,
          {
            ...options.sessionCookie
          }
        )
      );
    }
    // Opportunistically ensure CSRF cookie exists for authenticated browser sessions.
    if (csrfEnabled && csrfDoubleSubmitEnabled) {
      const csrf = getOrCreateCsrfToken(request);
      const single = csrf.headers.get('set-cookie');
      if (single) headers.append('set-cookie', single);
    }
    return { result, headers };
  };

  const requireUser = async (
    request: Request,
    opts: { redirectTo?: string } = {}
  ): Promise<RequireUserResult> => {
    const { result, headers } = await validate(request);
    if (!result.ok) {
      throw redirect(opts.redirectTo ?? '/login');
    }
    return { userId: result.userId as unknown as string, headers };
  };

  const logout = async (
    request: Request,
    opts: { redirectTo?: string } = {}
  ): Promise<Response> => {
    csrfCheckOrigin(request);
    assertDoubleSubmitCsrf(request);
    const token = getCookie(request, options.sessionCookie.name);
    if (token) await options.core.revokeSession({ sessionToken: token as unknown as SessionToken });
    const res = redirect(opts.redirectTo ?? '/login');
    res.headers.append(
      'set-cookie',
      serializeDeleteCookie(options.sessionCookie.name, { ...options.sessionCookie })
    );
    return res;
  };

  const passwordLogin = async (
    request: Request,
    opts: { redirectTo?: string } = {}
  ): Promise<Response> => {
    csrfCheckOrigin(request);
    let idKey: string | null = null;
    let clientKey: string | null = null;
    try {
      const form = await readForm(request);
      assertDoubleSubmitCsrf(request, String(form.get(csrfFormFieldName) ?? ''));
      const identifier = String(form.get('identifier') ?? '');
      const password = String(form.get('password') ?? '');
      idKey = `password_login:id:${identifier}`;
      const clientId = getClientId(request);
      clientKey = clientId ? `password_login:client:${clientId}` : null;

      enforceProgressiveDelay(idKey);
      if (clientKey) enforceProgressiveDelay(clientKey);

      enforceRateLimit(idKey, rules.passwordLoginPerIdentifier);
      if (clientId) enforceRateLimit(clientKey as string, rules.passwordLoginPerClient);

      const result = await options.core.loginPassword({
        identifier,
        password,
        sessionContext: sessionContextFromRequest(request)
      });
      if ('twoFactorRequired' in result && result.twoFactorRequired) {
        recordSuccess(idKey);
        if (clientKey) recordSuccess(clientKey);
        const res = redirect(twoFactorRedirectTo);
        res.headers.append(
          'set-cookie',
          serializeCookie(totpPendingCookie.name, result.pendingToken as unknown as string, {
            ...totpPendingCookie
          })
        );
        return res;
      }
      const { session } = result;
      recordSuccess(idKey);
      if (clientKey) recordSuccess(clientKey);
      const res = redirect(opts.redirectTo ?? '/');
      res.headers.append(
        'set-cookie',
        serializeCookie(options.sessionCookie.name, session.sessionToken as unknown as string, {
          ...options.sessionCookie
        })
      );
      return res;
    } catch (err) {
      if (isAuthError(err) && err.code === 'password_invalid') {
        if (idKey) recordFailure(idKey, progressiveRules.passwordLoginPerIdentifier);
        if (clientKey) recordFailure(clientKey, progressiveRules.passwordLoginPerClient);
      }
      return mapAuthError(err);
    }
  };

  const passwordRegister = async (
    request: Request,
    opts: { redirectTo?: string } = {}
  ): Promise<Response> => {
    csrfCheckOrigin(request);
    try {
      const form = await readForm(request);
      assertDoubleSubmitCsrf(request, String(form.get(csrfFormFieldName) ?? ''));
      const identifier = String(form.get('identifier') ?? '');
      const password = String(form.get('password') ?? '');
      const { session } = await options.core.registerPassword({
        identifier,
        password,
        sessionContext: sessionContextFromRequest(request)
      });
      const res = redirect(opts.redirectTo ?? '/');
      res.headers.append(
        'set-cookie',
        serializeCookie(options.sessionCookie.name, session.sessionToken as unknown as string, {
          ...options.sessionCookie
        })
      );
      return res;
    } catch (err) {
      return mapAuthError(err);
    }
  };

  const passkeyRegistrationStart = async (request: Request): Promise<Response> => {
    csrfCheckOrigin(request);
    try {
      const { userId, headers } = await requireUser(request);
      const body = await readJson<{
        userName: string;
        userDisplayName?: string;
        csrfToken?: string;
      }>(request);
      assertDoubleSubmitCsrf(request, body.csrfToken ?? null);
      const out = await options.core.startPasskeyRegistration({
        userId: userId as unknown as UserId,
        userName: body.userName,
        userDisplayName: body.userDisplayName
      });
      return json(out, { headers });
    } catch (err) {
      return mapAuthError(err);
    }
  };

  const passkeyRegistrationFinish = async (
    request: Request,
    opts: { redirectTo?: string } = {}
  ): Promise<Response> => {
    csrfCheckOrigin(request);
    try {
      const { userId, headers } = await requireUser(request);
      const body = await readJson<
        Omit<PasskeyRegistrationFinishInput, 'userId'> & { csrfToken?: string }
      >(request);
      assertDoubleSubmitCsrf(request, body.csrfToken ?? null);
      await options.core.finishPasskeyRegistration({
        userId: userId as unknown as UserId,
        challengeId: body.challengeId as unknown as ChallengeId,
        response: body.response
      });
      return redirect(opts.redirectTo ?? '/', { headers });
    } catch (err) {
      return mapAuthError(err);
    }
  };

  const passkeyLoginStart = async (request: Request): Promise<Response> => {
    csrfCheckOrigin(request);
    try {
      const body = await readJson<{ userId?: string; csrfToken?: string }>(request);
      assertDoubleSubmitCsrf(request, body.csrfToken ?? null);
      const out = await options.core.startPasskeyLogin({
        userId: body.userId ? (body.userId as unknown as UserId) : undefined
      });
      return json(out);
    } catch (err) {
      return mapAuthError(err);
    }
  };

  const passkeyLoginFinish = async (
    request: Request,
    opts: { redirectTo?: string } = {}
  ): Promise<Response> => {
    csrfCheckOrigin(request);
    let challengeKey: string | null = null;
    let clientKey: string | null = null;
    try {
      const body = await readJson<PasskeyLoginFinishInput>(request);
      // Allow token via header for JS clients; optional body.csrfToken also supported if present.
      assertDoubleSubmitCsrf(
        request,
        (body as unknown as { csrfToken?: string }).csrfToken ?? null
      );
      const clientId = getClientId(request);
      challengeKey = `passkey_finish:challenge:${body.challengeId as unknown as string}`;
      clientKey = clientId ? `passkey_finish:client:${clientId}` : null;

      enforceProgressiveDelay(challengeKey);
      if (clientKey) enforceProgressiveDelay(clientKey);

      enforceRateLimit(challengeKey, rules.passkeyFinishPerChallenge);
      if (clientKey) enforceRateLimit(clientKey, rules.passkeyFinishPerClient);

      const out = await options.core.finishPasskeyLogin({
        challengeId: body.challengeId as unknown as ChallengeId,
        response: body.response,
        sessionContext: sessionContextFromRequest(request)
      });
      if ('twoFactorRequired' in out && out.twoFactorRequired) {
        if (challengeKey) recordSuccess(challengeKey);
        if (clientKey) recordSuccess(clientKey);
        const res = redirect(twoFactorRedirectTo);
        res.headers.append(
          'set-cookie',
          serializeCookie(totpPendingCookie.name, out.pendingToken as unknown as string, {
            ...totpPendingCookie
          })
        );
        return res;
      }
      if (challengeKey) recordSuccess(challengeKey);
      if (clientKey) recordSuccess(clientKey);
      const res = redirect(opts.redirectTo ?? '/');
      res.headers.append(
        'set-cookie',
        serializeCookie(options.sessionCookie.name, out.session.sessionToken as unknown as string, {
          ...options.sessionCookie
        })
      );
      return res;
    } catch (err) {
      if (
        isAuthError(err) &&
        (err.code === 'passkey_invalid' || err.code === 'challenge_expired')
      ) {
        if (challengeKey) recordFailure(challengeKey, progressiveRules.passkeyFinishPerChallenge);
        if (clientKey) recordFailure(clientKey, progressiveRules.passkeyFinishPerClient);
      }
      return mapAuthError(err);
    }
  };

  const totpEnrollmentStart = async (request: Request): Promise<Response> => {
    csrfCheckOrigin(request);
    try {
      const { userId, headers } = await requireUser(request);
      const body = await readJson<{ accountName: string; csrfToken?: string }>(request);
      assertDoubleSubmitCsrf(request, body.csrfToken ?? null);
      const out = await options.core.startTotpEnrollment({
        userId: userId as unknown as UserId,
        accountName: body.accountName
      });
      return json(out, { headers });
    } catch (err) {
      return mapAuthError(err);
    }
  };

  const totpEnrollmentFinish = async (
    request: Request,
    opts: { redirectTo?: string } = {}
  ): Promise<Response> => {
    csrfCheckOrigin(request);
    try {
      const { userId, headers } = await requireUser(request);
      const body = await readJson<{ code: string; csrfToken?: string }>(request);
      assertDoubleSubmitCsrf(request, body.csrfToken ?? null);
      await options.core.finishTotpEnrollment({
        userId: userId as unknown as UserId,
        code: body.code
      });
      return redirect(opts.redirectTo ?? '/settings/security', { headers });
    } catch (err) {
      return mapAuthError(err);
    }
  };

  const totpVerify = async (
    request: Request,
    opts: { redirectTo?: string } = {}
  ): Promise<Response> => {
    csrfCheckOrigin(request);
    let pendingKey: string | null = null;
    let clientKey: string | null = null;
    try {
      const pending = getCookie(request, totpPendingCookie.name);
      if (!pending)
        throw new AuthError('unauthorized', 'Missing 2FA token', {
          publicMessage: 'Invalid code',
          status: 401
        });
      const form = await readForm(request);
      assertDoubleSubmitCsrf(request, String(form.get(csrfFormFieldName) ?? ''));
      const clientId = getClientId(request);
      pendingKey = `totp_verify:pending:${pending}`;
      clientKey = clientId ? `totp_verify:client:${clientId}` : null;

      enforceProgressiveDelay(pendingKey);
      if (clientKey) enforceProgressiveDelay(clientKey);

      enforceRateLimit(pendingKey, rules.totpVerifyPerPending);
      if (clientKey) enforceRateLimit(clientKey, rules.totpVerifyPerClient);

      const code = String(form.get('code') ?? '');
      const out = await options.core.verifyTotp({
        pendingToken: pending as unknown as ChallengeId,
        code,
        sessionContext: sessionContextFromRequest(request)
      });
      if (pendingKey) recordSuccess(pendingKey);
      if (clientKey) recordSuccess(clientKey);
      const res = redirect(opts.redirectTo ?? '/');
      res.headers.append(
        'set-cookie',
        serializeCookie(options.sessionCookie.name, out.session.sessionToken as unknown as string, {
          ...options.sessionCookie
        })
      );
      res.headers.append(
        'set-cookie',
        serializeDeleteCookie(totpPendingCookie.name, { ...totpPendingCookie })
      );
      return res;
    } catch (err) {
      if (isAuthError(err) && err.code === 'totp_invalid') {
        if (pendingKey) recordFailure(pendingKey, progressiveRules.totpVerifyPerPending);
        if (clientKey) recordFailure(clientKey, progressiveRules.totpVerifyPerClient);
      }
      return mapAuthError(err);
    }
  };

  return {
    validate,
    requireUser,
    logout,
    csrf: {
      getToken: (request: Request) => getOrCreateCsrfToken(request)
    },
    actions: {
      passwordLogin,
      passwordRegister,
      passkeyRegistrationStart,
      passkeyRegistrationFinish,
      passkeyLoginStart,
      passkeyLoginFinish,
      totpEnrollmentStart,
      totpEnrollmentFinish,
      totpVerify
    }
  };
}

function mapAuthError(err: unknown): Response {
  if (isAuthError(err)) {
    const headers = new Headers();
    if (err.code === 'rate_limited') {
      const cause: unknown = err.cause;
      const retryAfterMs =
        typeof cause === 'object' &&
        cause !== null &&
        'retryAfterMs' in cause &&
        typeof (cause as { retryAfterMs?: unknown }).retryAfterMs === 'number'
          ? (cause as { retryAfterMs: number }).retryAfterMs
          : null;
      if (retryAfterMs !== null) {
        headers.set('retry-after', String(Math.max(1, Math.ceil(retryAfterMs / 1000))));
      }
    }
    return json(
      {
        error: {
          code: err.code,
          message: err.publicMessage ?? 'Request failed'
        }
      },
      { status: err.status, headers }
    );
  }
  const unknown = new AuthError('internal_error', 'Unexpected error', {
    publicMessage: 'Request failed',
    status: 500,
    cause: err
  });
  return json(
    {
      error: {
        code: unknown.code,
        message: unknown.publicMessage
      }
    },
    { status: unknown.status }
  );
}
