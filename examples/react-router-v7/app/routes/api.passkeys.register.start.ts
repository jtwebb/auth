import { json, readJson } from '@jtwebb/auth/react-router';
import type { Route } from './+types/api.passkeys.register.start';
import { assertCsrf, auth, core } from '../auth.server';

export async function action({ request }: Route.ActionArgs) {
  assertCsrf(request);
  const { userId, headers } = await auth.requireUser(request, { redirectTo: '/login' });
  const body = await readJson<{ userName: string; userDisplayName?: string }>(request);
  const out = await core.startPasskeyRegistration({
    userId: userId as any,
    userName: body.userName,
    userDisplayName: body.userDisplayName
  });
  return json(out, { headers });
}

export default function PasskeyRegisterStart() {
  return null;
}
