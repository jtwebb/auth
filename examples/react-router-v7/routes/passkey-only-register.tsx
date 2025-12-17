import * as React from 'react';
import { createPasskeyFlows } from '../../../src/react/passkey-flows.js';

/**
 * Illustrative passkey-only signup UI:
 * - You still need a `userId` from the server (created without password).
 * - This example assumes your server returns { userId } from POST /api/users.
 */
export function PasskeyOnlyRegisterRoute() {
  const [identifier, setIdentifier] = React.useState('');
  const [userId, setUserId] = React.useState<string | null>(null);
  const [error, setError] = React.useState<string | null>(null);

  return (
    <div>
      <h1>Sign up with a passkey</h1>

      {!userId ? (
        <form
          onSubmit={async e => {
            e.preventDefault();
            setError(null);
            const res = await fetch('/api/users', {
              method: 'POST',
              headers: { 'content-type': 'application/json' },
              body: JSON.stringify({ identifier }),
              credentials: 'include'
            });
            if (!res.ok) return setError('Failed to create user');
            const data = (await res.json()) as { userId: string };
            setUserId(data.userId);
          }}
        >
          <label>
            Identifier
            <input
              value={identifier}
              onChange={e => setIdentifier(e.currentTarget.value)}
              autoComplete="username"
            />
          </label>
          <button type="submit">Continue</button>
        </form>
      ) : (
        <button
          type="button"
          onClick={async () => {
            setError(null);
            const flows = createPasskeyFlows({
              registrationStartUrl: '/api/passkeys/register/start',
              registrationFinishUrl: '/api/passkeys/register/finish',
              loginStartUrl: '/api/passkeys/login/start',
              loginFinishUrl: '/api/passkeys/login/finish'
            });

            await flows.register({
              userId,
              userName: identifier,
              userDisplayName: identifier
            });

            window.location.assign('/');
          }}
        >
          Create passkey
        </button>
      )}

      {error ? <div role="alert">{error}</div> : null}
    </div>
  );
}
