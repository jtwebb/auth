import { json, readJson } from '@jtwebb/auth/react-router';
import type { Route } from './+types/api.passkeys.register.finish';
import { assertCsrf, auth, core } from '../auth.server';

export async function action({ request }: Route.ActionArgs) {
  assertCsrf(request);
  const { userId, headers } = await auth.requireUser(request, { redirectTo: '/login' });
  const body = await readJson<{ challengeId: string; response: unknown }>(request);
  const out = await core.finishPasskeyRegistration({
    userId: userId as any,
    challengeId: body.challengeId as any,
    response: body.response as any
  });
  return json(out, { headers });
}

export default function PasskeyRegisterFinish() {
  return null;
}
