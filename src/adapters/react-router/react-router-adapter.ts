import type { AuthCore } from '../../core/create-auth-core.js';
import { AuthError, isAuthError } from '../../core/auth-error.js';
import type {
  ChallengeId,
  PasswordResetToken,
  SessionToken,
  UserId
} from '../../core/auth-types.js';
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
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import type { SecurityProfile } from '../../core/auth-policy.js';
import type { CookieOptions } from './cookies.js';
import { getCookie, serializeCookie, serializeDeleteCookie } from './cookies.js';
import { assertSameOrigin, json, readForm, readJson, redirect } from './http.js';

export type PasswordRegisterActionInput = {
  identifier: string;
  password: string;
  /**
   * Extra app-defined fields (e.g. invitationCode, displayName, marketingOptIn, ...).
   *
   * Note: the core register API only uses identifier/password; extra fields are for hooks.
   */
  [key: string]: unknown;
};

export type PasswordRegisterHookContext = {
  request: Request;
  form: FormData;
  /**
   * Client identifier used for per-client limits (e.g. IP), when enabled.
   */
  clientId: string | null;
  /**
   * Session binding context passed into core registration.
   */
  sessionContext: { clientId?: string; userAgent?: string };
};

export type PasswordRegisterHooks = {
  /**
   * Customize how the adapter reads registration input (to support extra fields).
   * Defaults to reading `identifier` and `password` from a form body.
   */
  readInput?: (
    ctx: PasswordRegisterHookContext
  ) => PasswordRegisterActionInput | Promise<PasswordRegisterActionInput>;
  /**
   * Run additional checks before calling `core.registerPassword` (e.g. validate/consume invite code).
   * Throw an `AuthError` to return a clean 4xx response.
   */
  beforeRegister?: (
    input: PasswordRegisterActionInput,
    ctx: PasswordRegisterHookContext
  ) => void | Promise<void>;
  /**
   * Best-effort hook after successful registration. Errors are swallowed to avoid creating an account
   * but returning an error to the client.
   */
  afterRegister?: (
    result: Awaited<ReturnType<AuthCore['registerPassword']>>,
    input: PasswordRegisterActionInput,
    ctx: PasswordRegisterHookContext
  ) => void | Promise<void>;
};

export type ReactRouterAuthAdapterOptions = {
  core: AuthCore;
  /**
   * Security presets that configure adapter defaults (CSRF strictness + rate limits/lockouts).
   * Defaults to "balanced".
   */
  securityProfile?: SecurityProfile;
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
     * If true, allow deriving a client id from proxy headers like `cf-connecting-ip` and
     * `x-forwarded-for`. Only enable this if you are behind a trusted proxy/CDN that overwrites
     * these headers; otherwise clients can spoof them and bypass per-client limits.
     *
     * Defaults to false.
     */
    trustProxyHeaders?: boolean;
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
  /**
   * Hooks for customizing `passwordRegister` (extra fields, invitation codes, business logic).
   */
  passwordRegister?: PasswordRegisterHooks;
};

export type ReactRouterAuthRateLimitRules = {
  passwordLoginPerIdentifier: RateLimitRule;
  passwordLoginPerClient: RateLimitRule;
  passwordRegisterPerIdentifier: RateLimitRule;
  passwordRegisterPerClient: RateLimitRule;
  passwordResetStartPerIdentifier: RateLimitRule;
  passwordResetStartPerClient: RateLimitRule;
  passwordResetFinishPerClient: RateLimitRule;
  passkeyLoginStartPerClient: RateLimitRule;
  passkeyRegisterStartPerClient: RateLimitRule;
  passkeyRegisterStartPerUser: RateLimitRule;
  totpVerifyPerPending: RateLimitRule;
  totpVerifyPerClient: RateLimitRule;
  passkeyFinishPerChallenge: RateLimitRule;
  passkeyFinishPerClient: RateLimitRule;
};

export type ReactRouterAuthProgressiveDelayRules = {
  passwordLoginPerIdentifier: ProgressiveDelayRule;
  passwordLoginPerClient: ProgressiveDelayRule;
  passwordRegisterPerIdentifier: ProgressiveDelayRule;
  passwordRegisterPerClient: ProgressiveDelayRule;
  passwordResetStartPerIdentifier: ProgressiveDelayRule;
  passwordResetStartPerClient: ProgressiveDelayRule;
  passwordResetFinishPerClient: ProgressiveDelayRule;
  passkeyLoginStartPerClient: ProgressiveDelayRule;
  passkeyRegisterStartPerClient: ProgressiveDelayRule;
  passkeyRegisterStartPerUser: ProgressiveDelayRule;
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
    passwordResetStart(request: Request, opts?: { redirectTo?: string }): Promise<Response>;
    passwordResetFinish(request: Request, opts?: { redirectTo?: string }): Promise<Response>;

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
  const securityProfile: SecurityProfile = options.securityProfile ?? 'balanced';
  const defaultCsrfAllowMissingOrigin: boolean = securityProfile === 'legacy';
  const defaultDoubleSubmitEnabled: boolean = securityProfile !== 'legacy';
  const defaultRateLimitEnabled: boolean = securityProfile !== 'legacy';
  const defaultProgressiveDelayEnabled: boolean = securityProfile !== 'legacy';

  const allowedOrigins = options.csrf?.allowedOrigins ?? options.core.policy.passkey.origins;
  const csrfEnabled = options.csrf?.enabled ?? true;
  const csrfAllowMissingOrigin = options.csrf?.allowMissingOrigin ?? defaultCsrfAllowMissingOrigin;
  const csrfDoubleSubmitEnabled = options.csrf?.doubleSubmit?.enabled ?? defaultDoubleSubmitEnabled;
  const csrfTokenCookie: CookieOptions = options.csrf?.doubleSubmit?.cookie ?? {
    name: 'csrf',
    path: '/',
    httpOnly: false,
    secure: true,
    sameSite: 'strict'
  };
  const csrfHeaderName = (options.csrf?.doubleSubmit?.headerName ?? 'x-csrf-token').toLowerCase();
  const csrfFormFieldName = options.csrf?.doubleSubmit?.formFieldName ?? 'csrfToken';
  const csrfJsonFieldName = options.csrf?.doubleSubmit?.jsonFieldName ?? 'csrfToken';
  const totpPendingCookie: CookieOptions = options.totpPendingCookie ?? {
    name: 'totp',
    path: '/',
    httpOnly: true,
    secure: true,
    sameSite: 'lax',
    maxAgeSeconds: 60 * 5
  };
  const twoFactorRedirectTo = options.twoFactorRedirectTo ?? '/two-factor';

  const rateLimitEnabled = options.rateLimit?.enabled ?? defaultRateLimitEnabled;
  const limiter: Pick<InMemoryRateLimiter, 'consume'> =
    options.rateLimit?.limiter ?? new InMemoryRateLimiter();
  const trustProxyHeaders = options.rateLimit?.trustProxyHeaders ?? false;
  const proxyHeaderClientId = (request: Request) => {
    const cf = request.headers.get('cf-connecting-ip');
    if (cf) return cf.trim();
    const xff = request.headers.get('x-forwarded-for');
    if (xff) return xff.split(',')[0]?.trim() ?? null;
    const xri = request.headers.get('x-real-ip');
    if (xri) return xri.trim();
    return null;
  };
  const getClientId =
    options.rateLimit?.getClientId ??
    ((request: Request) => {
      if (!trustProxyHeaders) return null;
      return proxyHeaderClientId(request);
    });
  const rules: ReactRouterAuthRateLimitRules = {
    // Defaults are intentionally conservative and intended to be safe across many apps.
    passwordLoginPerIdentifier: { windowMs: 15 * 60_000, max: 10 },
    passwordLoginPerClient: { windowMs: 15 * 60_000, max: 100 },
    passwordRegisterPerIdentifier: { windowMs: 15 * 60_000, max: 5 },
    passwordRegisterPerClient: { windowMs: 15 * 60_000, max: 50 },
    passwordResetStartPerIdentifier: { windowMs: 5 * 60_000, max: 5 },
    passwordResetStartPerClient: { windowMs: 5 * 60_000, max: 50 },
    passwordResetFinishPerClient: { windowMs: 5 * 60_000, max: 20 },
    passkeyLoginStartPerClient: { windowMs: 5 * 60_000, max: 60 },
    passkeyRegisterStartPerClient: { windowMs: 5 * 60_000, max: 30 },
    passkeyRegisterStartPerUser: { windowMs: 5 * 60_000, max: 10 },
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

  const progressiveDelayEnabled =
    options.rateLimit?.progressiveDelay?.enabled ?? defaultProgressiveDelayEnabled;
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
    passwordRegisterPerIdentifier: {
      failureWindowMs: 15 * 60_000,
      startAfterFailures: 2,
      baseDelayMs: 1_000,
      factor: 2,
      maxDelayMs: 30_000,
      lockoutAfterFailures: 10,
      lockoutMs: 15 * 60_000
    },
    passwordRegisterPerClient: {
      failureWindowMs: 15 * 60_000,
      startAfterFailures: 5,
      baseDelayMs: 500,
      factor: 2,
      maxDelayMs: 30_000,
      lockoutAfterFailures: 25,
      lockoutMs: 15 * 60_000
    },
    passwordResetStartPerIdentifier: {
      failureWindowMs: 5 * 60_000,
      startAfterFailures: 2,
      baseDelayMs: 1_000,
      factor: 2,
      maxDelayMs: 30_000,
      lockoutAfterFailures: 10,
      lockoutMs: 10 * 60_000
    },
    passwordResetStartPerClient: {
      failureWindowMs: 5 * 60_000,
      startAfterFailures: 5,
      baseDelayMs: 500,
      factor: 2,
      maxDelayMs: 30_000,
      lockoutAfterFailures: 50,
      lockoutMs: 10 * 60_000
    },
    passwordResetFinishPerClient: {
      failureWindowMs: 5 * 60_000,
      startAfterFailures: 3,
      baseDelayMs: 500,
      factor: 2,
      maxDelayMs: 30_000,
      lockoutAfterFailures: 25,
      lockoutMs: 10 * 60_000
    },
    passkeyLoginStartPerClient: {
      failureWindowMs: 5 * 60_000,
      startAfterFailures: 20,
      baseDelayMs: 250,
      factor: 2,
      maxDelayMs: 10_000,
      lockoutAfterFailures: 200,
      lockoutMs: 5 * 60_000
    },
    passkeyRegisterStartPerClient: {
      failureWindowMs: 5 * 60_000,
      startAfterFailures: 10,
      baseDelayMs: 500,
      factor: 2,
      maxDelayMs: 30_000,
      lockoutAfterFailures: 50,
      lockoutMs: 5 * 60_000
    },
    passkeyRegisterStartPerUser: {
      failureWindowMs: 5 * 60_000,
      startAfterFailures: 3,
      baseDelayMs: 1_000,
      factor: 2,
      maxDelayMs: 30_000,
      lockoutAfterFailures: 10,
      lockoutMs: 5 * 60_000
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
    const a = createHash('sha256').update(tokenFromCookie).digest();
    const b = createHash('sha256').update(token).digest();
    if (!timingSafeEqual(a, b)) {
      throw new AuthError('forbidden', 'CSRF protection: invalid token', {
        status: 403,
        publicMessage: 'Forbidden'
      });
    }
  };

  const readCsrfFromJsonBody = (body: unknown): string | null => {
    if (!body || typeof body !== 'object') return null;
    const anyBody = body as Record<string, unknown>;
    const v = anyBody[csrfJsonFieldName];
    if (typeof v === 'string' && v.trim()) return v.trim();
    // Backward-compatible default
    const legacy = anyBody['csrfToken'];
    if (typeof legacy === 'string' && legacy.trim()) return legacy.trim();
    return null;
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
    let idKey: string | null = null;
    let clientKey: string | null = null;
    try {
      const form = await readForm(request);
      assertDoubleSubmitCsrf(request, String(form.get(csrfFormFieldName) ?? ''));
      const clientId = getClientId(request);
      clientKey = clientId ? `password_register:client:${clientId}` : null;
      const sessionContext = sessionContextFromRequest(request);

      const hooks = options.passwordRegister;
      const input: PasswordRegisterActionInput = hooks?.readInput
        ? await hooks.readInput({ request, form, clientId, sessionContext })
        : {
            identifier: String(form.get('identifier') ?? ''),
            password: String(form.get('password') ?? '')
          };

      const identifier = String(input.identifier ?? '');
      const password = String(input.password ?? '');
      idKey = `password_register:id:${identifier}`;

      enforceProgressiveDelay(idKey);
      if (clientKey) enforceProgressiveDelay(clientKey);

      enforceRateLimit(idKey, rules.passwordRegisterPerIdentifier);
      if (clientKey) enforceRateLimit(clientKey, rules.passwordRegisterPerClient);

      if (hooks?.beforeRegister) {
        await hooks.beforeRegister(input, { request, form, clientId, sessionContext });
      }
      const result = await options.core.registerPassword({
        identifier,
        password,
        sessionContext
      });
      const { session } = result;
      recordSuccess(idKey);
      if (clientKey) recordSuccess(clientKey);

      if (hooks?.afterRegister) {
        try {
          await hooks.afterRegister(result, input, {
            request,
            form,
            clientId,
            sessionContext
          });
        } catch {
          // swallow (see docstring)
        }
      }
      const res = redirect(opts.redirectTo ?? '/');
      res.headers.append(
        'set-cookie',
        serializeCookie(options.sessionCookie.name, session.sessionToken as unknown as string, {
          ...options.sessionCookie
        })
      );
      return res;
    } catch (err) {
      if (isAuthError(err) && err.code === 'conflict') {
        if (idKey) recordFailure(idKey, progressiveRules.passwordRegisterPerIdentifier);
        if (clientKey) recordFailure(clientKey, progressiveRules.passwordRegisterPerClient);
      }
      return mapAuthError(err);
    }
  };

  const passwordResetStart = async (
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
      idKey = `password_reset_start:id:${identifier}`;
      const clientId = getClientId(request);
      clientKey = clientId ? `password_reset_start:client:${clientId}` : null;

      // For reset-start, treat repeated requests as abuse/spam: apply progressive delays too.
      enforceProgressiveDelay(idKey);
      if (clientKey) enforceProgressiveDelay(clientKey);
      enforceRateLimit(idKey, rules.passwordResetStartPerIdentifier);
      if (clientKey) enforceRateLimit(clientKey, rules.passwordResetStartPerClient);

      await options.core.startPasswordReset({ identifier });

      // Always record a "failure" to ramp backoff for repeated attempts (enumeration/spam hardening).
      recordFailure(idKey, progressiveRules.passwordResetStartPerIdentifier);
      if (clientKey) recordFailure(clientKey, progressiveRules.passwordResetStartPerClient);

      if (opts.redirectTo) return redirect(opts.redirectTo);
      return json({ ok: true });
    } catch (err) {
      return mapAuthError(err);
    }
  };

  const passwordResetFinish = async (
    request: Request,
    opts: { redirectTo?: string } = {}
  ): Promise<Response> => {
    csrfCheckOrigin(request);
    let clientKey: string | null = null;
    try {
      const form = await readForm(request);
      assertDoubleSubmitCsrf(request, String(form.get(csrfFormFieldName) ?? ''));
      const token = String(form.get('token') ?? '');
      const newPassword = String(form.get('newPassword') ?? '');
      const clientId = getClientId(request);
      clientKey = clientId ? `password_reset_finish:client:${clientId}` : null;

      if (clientKey) enforceProgressiveDelay(clientKey);
      if (clientKey) enforceRateLimit(clientKey, rules.passwordResetFinishPerClient);

      await options.core.resetPasswordWithToken({
        token: token as unknown as PasswordResetToken,
        newPassword
      });
      if (clientKey) recordSuccess(clientKey);

      if (opts.redirectTo) return redirect(opts.redirectTo);
      return json({ ok: true });
    } catch (err) {
      if (isAuthError(err) && err.code === 'password_reset_invalid') {
        if (clientKey) recordFailure(clientKey, progressiveRules.passwordResetFinishPerClient);
      }
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
      assertDoubleSubmitCsrf(request, readCsrfFromJsonBody(body));
      const clientId = getClientId(request);
      const userKey = `passkey_register_start:user:${userId}`;
      const clientKey = clientId ? `passkey_register_start:client:${clientId}` : null;
      enforceProgressiveDelay(userKey);
      if (clientKey) enforceProgressiveDelay(clientKey);
      enforceRateLimit(userKey, rules.passkeyRegisterStartPerUser);
      if (clientKey) enforceRateLimit(clientKey, rules.passkeyRegisterStartPerClient);
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
      assertDoubleSubmitCsrf(request, readCsrfFromJsonBody(body));
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
      assertDoubleSubmitCsrf(request, readCsrfFromJsonBody(body));
      const clientId = getClientId(request);
      const clientKey = clientId ? `passkey_login_start:client:${clientId}` : null;
      if (clientKey) {
        enforceProgressiveDelay(clientKey);
        enforceRateLimit(clientKey, rules.passkeyLoginStartPerClient);
      }
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
      assertDoubleSubmitCsrf(request, readCsrfFromJsonBody(body));
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
      assertDoubleSubmitCsrf(request, readCsrfFromJsonBody(body));
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
      assertDoubleSubmitCsrf(request, readCsrfFromJsonBody(body));
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
      passwordResetStart,
      passwordResetFinish,
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
