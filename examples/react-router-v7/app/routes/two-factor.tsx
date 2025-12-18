import { Form, Link } from 'react-router';
import { AuthError } from '@jtwebb/auth/core';
import {
  getCookie,
  json,
  readForm,
  redirect,
  serializeCookie,
  serializeDeleteCookie
} from '@jtwebb/auth/react-router';
import type { Route } from './+types/two-factor';
import { assertCsrf, auth, core, sessionCookie, storage, totpPendingCookie } from '../auth.server';

export async function action({ request }: Route.ActionArgs) {
  const form = await readForm(request);
  const method = String(form.get('method') ?? 'totp');

  if (method === 'backup') {
    return await backupCodeStepUp(request, String(form.get('code') ?? ''));
  }

  // Default: TOTP
  return await auth.actions.totpVerify(request, { redirectTo: '/' });
}

async function backupCodeStepUp(request: Request, code: string): Promise<Response> {
  assertCsrf(request);

  const pendingToken = getCookie(request, totpPendingCookie.name);
  if (!pendingToken) throw redirect('/login');

  const pending = await storage.challenges.consumeChallenge(pendingToken as any);
  if (!pending || pending.type !== 'totp_pending' || !pending.userId) {
    throw new AuthError('unauthorized', 'Invalid two-factor token', {
      publicMessage: 'Invalid code',
      status: 401
    });
  }
  if (pending.expiresAt.getTime() < Date.now()) {
    throw new AuthError('challenge_expired', 'Two-factor token expired', {
      publicMessage: 'Invalid code',
      status: 401
    });
  }

  await core.redeemBackupCode({ userId: pending.userId, code });

  const now = new Date();
  const session = core.createSessionToken();
  await storage.sessions.createSession({
    tokenHash: session.sessionTokenHash as any,
    userId: pending.userId,
    createdAt: now,
    lastSeenAt: now,
    expiresAt: new Date(now.getTime() + core.policy.session.absoluteTtlMs)
  });

  const res = redirect('/');
  res.headers.append(
    'set-cookie',
    serializeCookie(sessionCookie.name, session.sessionToken as any, { ...sessionCookie })
  );
  res.headers.append(
    'set-cookie',
    serializeDeleteCookie(totpPendingCookie.name, { ...totpPendingCookie })
  );
  return res;
}

export default function TwoFactor() {
  return (
    <main className="p-6 font-sans">
      <h1 className="text-xl font-semibold">Two-factor verification</h1>
      <p className="mt-2">Enter a TOTP code from your authenticator app, or use a backup code.</p>

      <Form method="post" className="mt-6 flex flex-col gap-3 max-w-sm">
        <label className="flex items-center gap-2">
          <input type="radio" name="method" value="totp" defaultChecked />
          <span>TOTP</span>
        </label>
        <label className="flex items-center gap-2">
          <input type="radio" name="method" value="backup" />
          <span>Backup code</span>
        </label>
        <label className="flex flex-col gap-1">
          <span>Code</span>
          <input name="code" inputMode="numeric" autoComplete="one-time-code" required />
        </label>
        <button type="submit">Verify</button>
      </Form>

      <p className="mt-6">
        <Link className="underline" to="/login">
          Back to login
        </Link>
      </p>
    </main>
  );
}

export async function loader({ request }: Route.LoaderArgs) {
  // Optional: if user already has a session, skip 2FA page.
  const { result, headers } = await auth.validate(request);
  if (result.ok) throw redirect('/');
  return json({}, { headers });
}
