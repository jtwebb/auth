import { AuthError } from '../../core/auth-error.js';

export type SameSite = 'lax' | 'strict' | 'none';

export type CookieOptions = {
  name: string;
  path?: string;
  domain?: string;
  httpOnly?: boolean;
  secure?: boolean;
  sameSite?: SameSite;
  maxAgeSeconds?: number;
};

export function parseCookieHeader(cookieHeader: string | null): Map<string, string> {
  const out = new Map<string, string>();
  if (!cookieHeader) return out;

  // Very small, safe parser: split on ';', then first '='
  const parts = cookieHeader.split(';'); // not RFC-perfect, good enough for session cookie values we set
  for (const part of parts) {
    const trimmed = part.trim();
    if (!trimmed) continue;
    const eq = trimmed.indexOf('=');
    if (eq === -1) continue;
    const name = trimmed.slice(0, eq).trim();
    const value = trimmed.slice(eq + 1).trim();
    if (!name) continue;
    out.set(name, decodeCookieValue(value));
  }
  return out;
}

export function getCookie(request: Request, name: string): string | null {
  const map = parseCookieHeader(request.headers.get('cookie'));
  return map.get(name) ?? null;
}

export function serializeCookie(
  name: string,
  value: string,
  options: Omit<CookieOptions, 'name'> = {}
): string {
  if (!name) throw new AuthError('invalid_input', 'cookie name is required');
  const enc = encodeCookieValue(value);

  const parts: string[] = [];
  parts.push(`${name}=${enc}`);
  const path = options.path ?? '/';
  parts.push(`Path=${path}`);

  if (options.domain) parts.push(`Domain=${options.domain}`);
  if (options.maxAgeSeconds !== undefined)
    parts.push(`Max-Age=${Math.floor(options.maxAgeSeconds)}`);

  const httpOnly = options.httpOnly ?? true;
  const secure = options.secure ?? true;
  const sameSite = options.sameSite ?? 'lax';

  validateCookieOptions({ name, path, domain: options.domain, secure, sameSite });

  if (httpOnly) parts.push('HttpOnly');
  if (secure) parts.push('Secure');
  parts.push(`SameSite=${capitalizeSameSite(sameSite)}`);

  return parts.join('; ');
}

export function serializeDeleteCookie(
  name: string,
  options: Omit<CookieOptions, 'name'> = {}
): string {
  // Expire immediately (Max-Age=0). Keep Path/Domain consistent with original cookie.
  return serializeCookie(name, '', { ...options, maxAgeSeconds: 0 });
}

function encodeCookieValue(value: string): string {
  // Our session tokens are base64url-safe; encodeURIComponent keeps it safe for general use.
  return encodeURIComponent(value);
}

function decodeCookieValue(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

function capitalizeSameSite(v: SameSite): string {
  switch (v) {
    case 'lax':
      return 'Lax';
    case 'strict':
      return 'Strict';
    case 'none':
      return 'None';
  }
}

function validateCookieOptions(ctx: {
  name: string;
  path: string;
  domain?: string;
  secure: boolean;
  sameSite: SameSite;
}): void {
  // Prefix rules (RFC 6265bis / common browser behavior):
  // - __Host-: must be Secure, Path=/, and MUST NOT include Domain attribute.
  // - __Secure-: must be Secure.
  if (ctx.name.startsWith('__Host-')) {
    if (!ctx.secure) throw new AuthError('invalid_input', '__Host- cookies must set secure=true');
    if (ctx.path !== '/')
      throw new AuthError('invalid_input', '__Host- cookies must have path="/"');
    if (ctx.domain) throw new AuthError('invalid_input', '__Host- cookies must not set a domain');
  }
  if (ctx.name.startsWith('__Secure-')) {
    if (!ctx.secure) throw new AuthError('invalid_input', '__Secure- cookies must set secure=true');
  }
  // SameSite=None requires Secure in modern browsers.
  if (ctx.sameSite === 'none' && !ctx.secure) {
    throw new AuthError('invalid_input', 'SameSite=None cookies must set secure=true');
  }
}
