import { Link } from 'react-router';
import { json } from '@jtwebb/auth/react-router';
import type { Route } from './+types/home';
import { auth } from '../auth.server';

export async function loader({ request }: Route.LoaderArgs) {
  const { result, headers } = await auth.validate(request);
  return json(
    {
      userId: result.ok ? (result.userId as unknown as string) : null
    },
    { headers }
  );
}

export default function Home({ loaderData }: Route.ComponentProps) {
  return (
    <main className="p-6 font-sans">
      <h1 className="text-xl font-semibold">Auth example</h1>

      <p className="mt-2">
        Status:{' '}
        <strong>{loaderData.userId ? `signed in (${loaderData.userId})` : 'signed out'}</strong>
      </p>

      <nav className="mt-4 flex gap-4">
        <Link className="underline" to="/register">
          Register
        </Link>
        <Link className="underline" to="/login">
          Login
        </Link>
        <Link className="underline" to="/settings/security">
          Security settings (2FA, passkeys, backup codes)
        </Link>
        <Link className="underline" to="/protected">
          Protected page
        </Link>
      </nav>

      {loaderData.userId ? (
        <form className="mt-6" action="/logout" method="post">
          <button type="submit">Logout</button>
        </form>
      ) : null}
    </main>
  );
}
