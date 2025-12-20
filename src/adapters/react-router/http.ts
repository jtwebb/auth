import { AuthError } from '../../core/auth-error.js';

export function json(data: unknown, init: ResponseInit & { headers?: HeadersInit } = {}): Response {
  const headers = new Headers(init.headers);
  if (!headers.has('content-type')) headers.set('content-type', 'application/json; charset=utf-8');
  return new Response(JSON.stringify(data), { ...init, headers });
}

export function redirect(
  location: string,
  init: ResponseInit & { headers?: HeadersInit } = {}
): Response {
  const headers = new Headers(init.headers);
  headers.set('location', location);
  return new Response(null, { ...init, status: init.status ?? 302, headers });
}

export async function readJson<T = unknown>(request: Request): Promise<T> {
  const ct = request.headers.get('content-type') ?? '';
  if (!ct.includes('application/json')) {
    throw new AuthError('invalid_input', 'Expected application/json request body');
  }
  return (await request.json()) as T;
}

export async function readForm(request: Request): Promise<FormData> {
  const ct = request.headers.get('content-type') ?? '';
  if (!ct.includes('application/x-www-form-urlencoded') && !ct.includes('multipart/form-data')) {
    throw new AuthError('invalid_input', 'Expected form-encoded request body');
  }
  return await request.formData();
}

export type SameOriginOptions = {
  /**
   * If true, allow requests that omit both Origin and Referer (e.g. some non-browser clients).
   * For browser-based auth endpoints, prefer false.
   */
  allowMissingOrigin?: boolean;
  /**
   * If true (default), fall back to validating Referer when Origin is missing.
   */
  allowRefererFallback?: boolean;
};

export function assertSameOrigin(
  request: Request,
  allowedOrigins: readonly string[],
  options: SameOriginOptions = {}
): void {
  // For state-changing actions, ensure request came from our own site(s).
  // Origin is present for fetch/XHR and most form POSTs in modern browsers.
  const origin = request.headers.get('origin');
  if (origin) {
    if (!allowedOrigins.includes(origin)) {
      throw new AuthError('forbidden', 'CSRF protection: invalid origin', {
        status: 403,
        publicMessage: 'Forbidden'
      });
    }
    return;
  }

  const allowRefererFallback = options.allowRefererFallback ?? true;
  if (allowRefererFallback) {
    const referer = request.headers.get('referer');
    if (referer) {
      let refererOrigin: string | null = null;
      try {
        refererOrigin = new URL(referer).origin;
      } catch {
        refererOrigin = null;
      }
      if (!refererOrigin || !allowedOrigins.includes(refererOrigin)) {
        throw new AuthError('forbidden', 'CSRF protection: invalid referer', {
          status: 403,
          publicMessage: 'Forbidden'
        });
      }
      return;
    }
  }

  if (options.allowMissingOrigin) return;
  throw new AuthError('forbidden', 'CSRF protection: missing origin', {
    status: 403,
    publicMessage: 'Forbidden'
  });
}
