import { startAuthentication } from '@simplewebauthn/browser';
import { useEffect, useMemo, useState } from 'react';
import { Form, Link, useFetcher, useNavigate } from 'react-router';
import type { Route } from './+types/login';

type PasskeyLoginStartResult = { challengeId: string; options: any };
type PasskeyLoginFinishResult = { twoFactorRequired: true } | { twoFactorRequired?: false };

export default function Login() {
  const navigate = useNavigate();
  const passkeyStart = useFetcher<PasskeyLoginStartResult>();
  const passkeyFinish = useFetcher<PasskeyLoginFinishResult>();
  const [passkeyError, setPasskeyError] = useState<string | null>(null);

  const canStartPasskey = passkeyStart.state === 'idle' && passkeyFinish.state === 'idle';

  const startPasskeyLogin = () => {
    setPasskeyError(null);
    passkeyStart.submit(
      {},
      {
        method: 'post',
        action: '/api/passkeys/login/start',
        encType: 'application/json'
      }
    );
  };

  useEffect(() => {
    const run = async () => {
      if (!passkeyStart.data) return;
      try {
        const resp = await startAuthentication(passkeyStart.data.options);
        passkeyFinish.submit(
          { challengeId: passkeyStart.data.challengeId, response: resp },
          {
            method: 'post',
            action: '/api/passkeys/login/finish',
            encType: 'application/json'
          }
        );
      } catch (err) {
        setPasskeyError(err instanceof Error ? err.message : 'Passkey login failed');
      }
    };
    void run();
  }, [passkeyStart.data]);

  useEffect(() => {
    if (!passkeyFinish.data) return;
    if ('twoFactorRequired' in passkeyFinish.data && passkeyFinish.data.twoFactorRequired) {
      navigate('/two-factor');
    } else {
      navigate('/');
    }
  }, [passkeyFinish.data, navigate]);

  const busyLabel = useMemo(() => {
    if (passkeyStart.state !== 'idle') return 'Starting passkey…';
    if (passkeyFinish.state !== 'idle') return 'Finishing passkey…';
    return 'Login with passkey';
  }, [passkeyFinish.state, passkeyStart.state]);

  return (
    <main className="p-6 font-sans">
      <h1 className="text-xl font-semibold">Login</h1>

      <section className="mt-6">
        <h2 className="font-semibold">Password login</h2>
        <Form method="post" action="/login" className="mt-3 flex flex-col gap-3 max-w-sm">
          <label className="flex flex-col gap-1">
            <span>Identifier</span>
            <input name="identifier" autoComplete="username" required />
          </label>
          <label className="flex flex-col gap-1">
            <span>Password</span>
            <input name="password" type="password" autoComplete="current-password" required />
          </label>
          <button type="submit">Login with password</button>
        </Form>
        <p className="mt-3 text-sm">
          If 2FA is enabled, you’ll be redirected to <code>/two-factor</code>.
        </p>
      </section>

      <section className="mt-10">
        <h2 className="font-semibold">Passkey login</h2>
        <button
          className="mt-3"
          type="button"
          onClick={startPasskeyLogin}
          disabled={!canStartPasskey}
        >
          {busyLabel}
        </button>
        {passkeyError ? <p className="mt-2 text-sm">Error: {passkeyError}</p> : null}
      </section>

      <p className="mt-10">
        Need an account?{' '}
        <Link className="underline" to="/register">
          Register
        </Link>
      </p>
    </main>
  );
}

export async function action({ request }: Route.ActionArgs) {
  return await (
    await import('../auth.server')
  ).auth.actions.passwordLogin(request, {
    redirectTo: '/'
  });
}
