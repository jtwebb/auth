import { describe, expect, it, vi } from 'vitest';
import { createTotpFlows } from '../../src/react/totp-flows.js';

describe('react/totp-flows', () => {
  it('startEnrollment and finishEnrollment call JSON endpoints', async () => {
    const fetchFn = vi.fn(async (url: any, init: any) => {
      if (String(url).endsWith('/totp/start')) {
        const body = JSON.parse(init.body);
        expect(body.userId).toBe('u1');
        return new Response(
          JSON.stringify({ userId: 'u1', secretBase32: 'ABC', otpauthUri: 'otpauth://totp/x' }),
          {
            status: 200
          }
        );
      }
      if (String(url).endsWith('/totp/finish')) {
        return new Response(JSON.stringify({ ok: true }), { status: 200 });
      }
      return new Response('no', { status: 404 });
    });

    const flows = createTotpFlows(
      {
        enrollmentStartUrl: '/totp/start',
        enrollmentFinishUrl: '/totp/finish',
        verifyUrl: '/totp/verify'
      },
      { fetchFn }
    );

    const start = await flows.startEnrollment({ userId: 'u1', accountName: 'a@example.com' });
    expect(start.otpauthUri).toContain('otpauth://');
    await flows.finishEnrollment({ userId: 'u1', code: '123456' });
  });

  it('verify posts form body', async () => {
    const fetchFn = vi.fn(async (_url: any, init: any) => {
      expect(String(init.headers['content-type'] ?? init.headers.get?.('content-type'))).toContain(
        'application/x-www-form-urlencoded'
      );
      expect(String(init.body)).toContain('code=123456');
      return new Response('', { status: 200 });
    });

    const flows = createTotpFlows(
      { enrollmentStartUrl: '', enrollmentFinishUrl: '', verifyUrl: '/totp/verify' },
      { fetchFn }
    );
    await flows.verify('123456');
  });
});
