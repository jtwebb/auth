import type { Route } from './+types/logout';
import { auth } from '../auth.server';

export async function action({ request }: Route.ActionArgs) {
  return await auth.logout(request, { redirectTo: '/login' });
}

export default function Logout() {
  // This route is action-only; render nothing.
  return null;
}
