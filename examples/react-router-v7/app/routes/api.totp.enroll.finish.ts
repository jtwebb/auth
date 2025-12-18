import { json, readJson } from '@jtwebb/auth/react-router';
import type { Route } from './+types/api.totp.enroll.finish';
import { assertCsrf, auth, core } from '../auth.server';

export async function action({ request }: Route.ActionArgs) {
  assertCsrf(request);
  const { userId, headers } = await auth.requireUser(request, { redirectTo: '/login' });
  const body = await readJson<{ code: string }>(request);
  const out = await core.finishTotpEnrollment({ userId: userId as any, code: body.code });
  return json(out, { headers });
}

export default function TotpEnrollFinish() {
  return null;
}
