import * as React from 'react';

/**
 * Illustrative registration page using the password register endpoint.
 * In a real RRv7 app you'd likely post to an action instead of calling fetch directly.
 */
export function RegisterRoute() {
  const [identifier, setIdentifier] = React.useState('');
  const [password, setPassword] = React.useState('');
  const [error, setError] = React.useState<string | null>(null);

  return (
    <div>
      <h1>Create account</h1>
      <form
        method="post"
        onSubmit={async e => {
          e.preventDefault();
          setError(null);
          const res = await fetch('/api/auth/register', {
            method: 'POST',
            headers: { 'content-type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({ identifier, password }),
            credentials: 'include'
          });
          if (!res.ok) setError('Registration failed');
          else window.location.assign('/');
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
        <label>
          Password
          <input
            value={password}
            onChange={e => setPassword(e.currentTarget.value)}
            type="password"
            autoComplete="new-password"
          />
        </label>
        <button type="submit">Create account</button>
      </form>
      {error ? <div role="alert">{error}</div> : null}
    </div>
  );
}
