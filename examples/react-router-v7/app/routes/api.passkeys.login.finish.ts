import { json, readJson, serializeCookie } from '@jtwebb/auth/react-router';
import type { Route } from './+types/api.passkeys.login.finish';
import { assertCsrf, core, sessionCookie, totpPendingCookie } from '../auth.server';

export async function action({ request }: Route.ActionArgs) {
  assertCsrf(request);
  const body = await readJson<{ challengeId: string; response: unknown }>(request);
  const out = await core.finishPasskeyLogin({
    challengeId: body.challengeId as any,
    response: body.response as any
  });

  const res = json({
    twoFactorRequired: 'twoFactorRequired' in out && out.twoFactorRequired ? true : false
  });

  if ('twoFactorRequired' in out && out.twoFactorRequired) {
    res.headers.append(
      'set-cookie',
      serializeCookie(totpPendingCookie.name, out.pendingToken as any, { ...totpPendingCookie })
    );
    return res;
  }

  res.headers.append(
    'set-cookie',
    serializeCookie(sessionCookie.name, out.session.sessionToken as any, { ...sessionCookie })
  );
  return res;
}

export default function PasskeyLoginFinish() {
  return null;
}
