import { Form, Link } from 'react-router';
import type { Route } from './+types/register';
import { auth } from '../auth.server';

export async function action({ request }: Route.ActionArgs) {
  // CSRF protection (Origin check) + cookie session issuance is handled by the adapter.
  return await auth.actions.passwordRegister(request, { redirectTo: '/' });
}

export default function Register() {
  return (
    <main className="p-6 font-sans">
      <h1 className="text-xl font-semibold">Register (password)</h1>
      <p className="mt-2">
        After you register, go to{' '}
        <Link className="underline" to="/settings/security">
          Security
        </Link>{' '}
        to add a passkey, enable 2FA, and rotate backup codes.
      </p>

      <Form method="post" className="mt-6 flex flex-col gap-3 max-w-sm">
        <label className="flex flex-col gap-1">
          <span>Identifier (email/username)</span>
          <input name="identifier" autoComplete="username" required />
        </label>
        <label className="flex flex-col gap-1">
          <span>Password</span>
          <input name="password" type="password" autoComplete="new-password" required />
        </label>
        <button type="submit">Create account</button>
      </Form>

      <p className="mt-6">
        Already have an account?{' '}
        <Link className="underline" to="/login">
          Login
        </Link>
      </p>
    </main>
  );
}
