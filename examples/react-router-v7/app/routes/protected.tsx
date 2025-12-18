import { json } from '@jtwebb/auth/react-router';
import type { Route } from './+types/protected';
import { auth } from '../auth.server';

export async function loader({ request }: Route.LoaderArgs) {
  const { userId, headers } = await auth.requireUser(request, { redirectTo: '/login' });
  return json({ userId }, { headers });
}

export default function Protected({ loaderData }: Route.ComponentProps) {
  return (
    <main className="p-6 font-sans">
      <h1 className="text-xl font-semibold">Protected page</h1>
      <p className="mt-2">
        You are authenticated as <strong>{loaderData.userId}</strong>.
      </p>
    </main>
  );
}
