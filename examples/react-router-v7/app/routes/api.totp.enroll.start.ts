import { json, readJson } from '@jtwebb/auth/react-router';
import type { Route } from './+types/api.totp.enroll.start';
import { assertCsrf, auth, core } from '../auth.server';

export async function action({ request }: Route.ActionArgs) {
  assertCsrf(request);
  const { userId, headers } = await auth.requireUser(request, { redirectTo: '/login' });
  const body = await readJson<{ accountName: string }>(request);
  const out = await core.startTotpEnrollment({
    userId: userId as any,
    accountName: body.accountName
  });
  return json(out, { headers });
}

export default function TotpEnrollStart() {
  return null;
}
