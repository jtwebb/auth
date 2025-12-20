import { describe, expect, it } from 'vitest';
import {
  getCookie,
  parseCookieHeader,
  serializeCookie,
  serializeDeleteCookie
} from '../../../src/adapters/react-router/cookies.js';

describe('adapters/react-router/cookies', () => {
  it('parses cookie header', () => {
    const m = parseCookieHeader('a=1; b=two%20words; c=3');
    expect(m.get('a')).toBe('1');
    expect(m.get('b')).toBe('two words');
    expect(m.get('c')).toBe('3');
  });

  it('gets cookie from Request', () => {
    const req = new Request('https://example.com', { headers: { cookie: 'sid=abc' } });
    expect(getCookie(req, 'sid')).toBe('abc');
    expect(getCookie(req, 'missing')).toBeNull();
  });

  it('serializes cookies with secure defaults', () => {
    const header = serializeCookie('sid', 'tok', { path: '/' });
    expect(header).toContain('sid=tok');
    expect(header).toContain('HttpOnly');
    expect(header).toContain('Secure');
    expect(header).toContain('SameSite=Lax');
  });

  it('serializes delete cookie', () => {
    const header = serializeDeleteCookie('sid', { path: '/' });
    expect(header).toContain('Max-Age=0');
  });

  it('enforces __Host- cookie prefix rules', () => {
    expect(() => serializeCookie('__Host-sid', 'tok', { path: '/', secure: true })).not.toThrow();

    expect(() => serializeCookie('__Host-sid', 'tok', { path: '/x', secure: true })).toThrow(
      /__Host- cookies must have path="\/"/
    );

    expect(() =>
      serializeCookie('__Host-sid', 'tok', { path: '/', secure: true, domain: 'example.com' })
    ).toThrow(/__Host- cookies must not set a domain/);

    expect(() => serializeCookie('__Host-sid', 'tok', { path: '/', secure: false })).toThrow(
      /__Host- cookies must set secure=true/
    );
  });

  it('enforces SameSite=None requires Secure', () => {
    expect(() =>
      serializeCookie('sid', 'tok', { path: '/', sameSite: 'none', secure: false })
    ).toThrow(/SameSite=None cookies must set secure=true/);
  });
});
