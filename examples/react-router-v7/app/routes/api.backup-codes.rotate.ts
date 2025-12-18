import { json } from '@jtwebb/auth/react-router';
import type { Route } from './+types/api.backup-codes.rotate';
import { assertCsrf, auth, core } from '../auth.server';

export async function action({ request }: Route.ActionArgs) {
  assertCsrf(request);
  const { userId, headers } = await auth.requireUser(request, { redirectTo: '/login' });
  const out = await core.rotateBackupCodes({ userId: userId as any });
  return json(out, { headers });
}

export default function BackupCodesRotate() {
  return null;
}
