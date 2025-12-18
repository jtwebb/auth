import { json, readJson } from '@jtwebb/auth/react-router';
import type { Route } from './+types/api.passkeys.login.start';
import { assertCsrf, core } from '../auth.server';

export async function action({ request }: Route.ActionArgs) {
  assertCsrf(request);
  const body = await readJson<{ userId?: string }>(request);
  const out = await core.startPasskeyLogin({ userId: body.userId as any });
  return json(out);
}

export default function PasskeyLoginStart() {
  return null;
}
