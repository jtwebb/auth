import { startRegistration } from '@simplewebauthn/browser';
import { useEffect, useMemo, useState } from 'react';
import { Form, useFetcher } from 'react-router';
import { json, readForm, redirect } from '@jtwebb/auth/react-router';
import type { Route } from './+types/settings.security';
import { assertCsrf, auth, storage } from '../auth.server';

type TotpStart = { secretBase32: string; otpauthUri: string };
type BackupCodesRotate = { codes: string[] };
type PasskeyStart = { challengeId: string; options: any };

export async function loader({ request }: Route.LoaderArgs) {
  const { userId, headers } = await auth.requireUser(request, { redirectTo: '/login' });

  const [totpEnabled, backupCodesRemaining, passkeyCount] = await Promise.all([
    storage.totp.getEnabled(userId as any).then(Boolean),
    storage.backupCodes.countRemaining(userId as any),
    storage.webauthn.listCredentialsForUser(userId as any).then(list => list.length)
  ]);

  return json(
    {
      userId,
      totpEnabled,
      backupCodesRemaining,
      passkeyCount
    },
    { headers }
  );
}

export async function action({ request }: Route.ActionArgs) {
  const { userId } = await auth.requireUser(request, { redirectTo: '/login' });
  assertCsrf(request);

  const form = await readForm(request);
  const intent = String(form.get('intent') ?? '');

  if (intent === 'totp_disable') {
    await storage.totp.disable(userId as any, new Date());
    throw redirect('/settings/security');
  }

  throw redirect('/settings/security');
}

export default function SecuritySettings({ loaderData }: Route.ComponentProps) {
  const passkeyStart = useFetcher<PasskeyStart>();
  const passkeyFinish = useFetcher<any>();

  const totpStart = useFetcher<TotpStart>();
  const totpFinish = useFetcher<any>();

  const rotateBackupCodes = useFetcher<BackupCodesRotate>();

  const [passkeyUserName, setPasskeyUserName] = useState('user');
  const [passkeyDisplayName, setPasskeyDisplayName] = useState('');

  const [totpAccountName, setTotpAccountName] = useState('user@example.com');
  const [totpCode, setTotpCode] = useState('');

  const startPasskey = () => {
    passkeyStart.submit(
      { userName: passkeyUserName, userDisplayName: passkeyDisplayName || undefined },
      { method: 'post', action: '/api/passkeys/register/start', encType: 'application/json' }
    );
  };

  useEffect(() => {
    const run = async () => {
      if (!passkeyStart.data) return;
      const resp = await startRegistration(passkeyStart.data.options);
      passkeyFinish.submit(
        { challengeId: passkeyStart.data.challengeId, response: resp },
        { method: 'post', action: '/api/passkeys/register/finish', encType: 'application/json' }
      );
    };
    void run();
  }, [passkeyStart.data]);

  const startTotp = () => {
    totpStart.submit(
      { accountName: totpAccountName },
      { method: 'post', action: '/api/totp/enroll/start', encType: 'application/json' }
    );
  };

  const finishTotp = () => {
    totpFinish.submit(
      { code: totpCode },
      { method: 'post', action: '/api/totp/enroll/finish', encType: 'application/json' }
    );
  };

  const rotateCodes = () => {
    rotateBackupCodes.submit(
      {},
      { method: 'post', action: '/api/backup-codes/rotate', encType: 'application/json' }
    );
  };

  const busyPasskey = passkeyStart.state !== 'idle' || passkeyFinish.state !== 'idle';
  const busyTotp = totpStart.state !== 'idle' || totpFinish.state !== 'idle';

  const totpStartSummary = useMemo(() => {
    if (!totpStart.data) return null;
    return (
      <div className="mt-3 text-sm">
        <p>
          Save this secret in your authenticator app. (In a real app you’d show a QR code generated
          from <code>otpauthUri</code>.)
        </p>
        <p className="mt-2">
          <strong>secretBase32:</strong> <code>{totpStart.data.secretBase32}</code>
        </p>
        <p className="mt-2">
          <strong>otpauthUri:</strong> <code>{totpStart.data.otpauthUri}</code>
        </p>
      </div>
    );
  }, [totpStart.data]);

  return (
    <main className="p-6 font-sans">
      <h1 className="text-xl font-semibold">Security settings</h1>
      <p className="mt-2">
        Signed in as <strong>{loaderData.userId}</strong>
      </p>

      <section className="mt-8">
        <h2 className="font-semibold">Passkeys</h2>
        <p className="mt-2 text-sm">
          Registered passkeys: <strong>{loaderData.passkeyCount}</strong>
        </p>

        <div className="mt-4 flex flex-col gap-3 max-w-md">
          <label className="flex flex-col gap-1">
            <span>userName (required)</span>
            <input value={passkeyUserName} onChange={e => setPasskeyUserName(e.target.value)} />
          </label>
          <label className="flex flex-col gap-1">
            <span>userDisplayName (optional)</span>
            <input
              value={passkeyDisplayName}
              onChange={e => setPasskeyDisplayName(e.target.value)}
            />
          </label>
          <button type="button" onClick={startPasskey} disabled={busyPasskey}>
            {busyPasskey ? 'Working…' : 'Register a passkey'}
          </button>
        </div>
      </section>

      <section className="mt-10">
        <h2 className="font-semibold">Two-factor authentication (TOTP)</h2>
        <p className="mt-2 text-sm">
          Status: <strong>{loaderData.totpEnabled ? 'enabled' : 'disabled'}</strong>
        </p>

        {!loaderData.totpEnabled ? (
          <div className="mt-4 max-w-md">
            <label className="flex flex-col gap-1">
              <span>Account name (label in authenticator)</span>
              <input value={totpAccountName} onChange={e => setTotpAccountName(e.target.value)} />
            </label>
            <button className="mt-3" type="button" onClick={startTotp} disabled={busyTotp}>
              {busyTotp ? 'Working…' : 'Start enrollment'}
            </button>
            {totpStartSummary}
            {totpStart.data ? (
              <div className="mt-4 flex flex-col gap-2">
                <label className="flex flex-col gap-1">
                  <span>Enter a code to confirm</span>
                  <input value={totpCode} onChange={e => setTotpCode(e.target.value)} />
                </label>
                <button type="button" onClick={finishTotp} disabled={busyTotp}>
                  Finish enrollment
                </button>
              </div>
            ) : null}
          </div>
        ) : (
          <Form method="post" className="mt-4">
            <input type="hidden" name="intent" value="totp_disable" />
            <button type="submit">Disable 2FA</button>
          </Form>
        )}
      </section>

      <section className="mt-10">
        <h2 className="font-semibold">Backup codes</h2>
        <p className="mt-2 text-sm">
          Remaining: <strong>{loaderData.backupCodesRemaining}</strong>
        </p>
        <button className="mt-3" type="button" onClick={rotateCodes}>
          Rotate backup codes
        </button>

        {rotateBackupCodes.data?.codes ? (
          <div className="mt-3">
            <p className="text-sm">
              Store these securely — this is the only time you’ll see plaintext codes.
            </p>
            <ul className="mt-2 text-sm">
              {rotateBackupCodes.data.codes.map(c => (
                <li key={c}>
                  <code>{c}</code>
                </li>
              ))}
            </ul>
          </div>
        ) : null}
      </section>
    </main>
  );
}
